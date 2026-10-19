#include "posix.h"
#include "rut/runtime/callbacks_impl.h"
#include "rut/runtime/epoll_event_loop.h"
#include "rut/runtime/iouring_event_loop.h"
#include "rut/runtime/shard.h"
#include "test.h"
#include "test_helpers.h"

#include <nghttp2/nghttp2.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#if RUT_GRPC_JIT
#include "rut/serve_loader.h"
#endif
#include <atomic>
#include <memory>

#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sys/mman.h>

using namespace rut;

namespace {
volatile sig_atomic_t grpc_test_signal_count = 0;
void grpc_test_signal_handler(int) {
    grpc_test_signal_count = grpc_test_signal_count + 1;
}

u64 grpc_jit_forward(void*, jit::HandlerCtx*, const u8*, u32, void*) {
    return jit::HandlerResult::make_forward(0).pack();
}
u64 grpc_jit_mutating_forward(void* conn, jit::HandlerCtx* ctx, const u8*, u32, void*) {
    if (ctx->state == 0) {
        auto* c = static_cast<Connection*>(conn);
        c->resp_header_mutations[0] = {
            {"x-jit", 5}, {"first", 5}, Connection::RespHeaderMutationMode::Set};
        c->resp_header_mutations[1] = {
            {"x-remove", 8}, {nullptr, 0}, Connection::RespHeaderMutationMode::Remove};
        c->resp_header_mutation_count = 2;
        return jit::HandlerResult::make_yield_payload(1, jit::YieldKind::Timer, 1).pack();
    }
    return jit::HandlerResult::make_forward(0).pack();
}
u64 grpc_jit_timer_forward(void*, jit::HandlerCtx* ctx, const u8*, u32, void*) {
    if (ctx->state == 0)
        return jit::HandlerResult::make_yield_payload(1, jit::YieldKind::Timer, 100).pack();
    return jit::HandlerResult::make_forward(0).pack();
}

struct GrpcBackendHealthReset {
    GrpcBackendHealthReset() { reset(); }
    ~GrpcBackendHealthReset() { reset(); }
    static void reset() {
        for (u16 uid = 0; uid < RouteConfig::kMaxUpstreams; uid++)
            for (u32 bid = 0; bid < UpstreamTarget::kMaxBackends; bid++) {
                auto* h = backend_health(uid, bid);
                h->fails = 0;
                h->eject_until_us = 0;
                h->active_down = false;
            }
    }
};

void set_socket_timeouts(int fd, int secs) {
    timeval timeout{secs, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
}
bool write_all_fd(int fd, const u8* data, u32 n) {
    while (n) {
        const ssize_t sent = send(fd, data, n, MSG_NOSIGNAL);
        if (sent < 0 && errno == EINTR) continue;
        if (sent <= 0) return false;
        data += sent;
        n -= static_cast<u32>(sent);
    }
    return true;
}
nghttp2_nv nv(const char* name, const char* value) {
    return {reinterpret_cast<uint8_t*>(const_cast<char*>(name)),
            reinterpret_cast<uint8_t*>(const_cast<char*>(value)),
            strlen(name),
            strlen(value),
            NGHTTP2_NV_FLAG_NONE};
}
bool flush_session(nghttp2_session* session, int fd, SSL* ssl = nullptr) {
    const uint8_t* data;
    ssize_t n;
    while ((n = nghttp2_session_mem_send(session, &data)) > 0) {
        if (!ssl) {
            if (!write_all_fd(fd, data, static_cast<u32>(n))) return false;
        } else {
            ssize_t offset = 0;
            while (offset < n) {
                const int sent = SSL_write(ssl, data + offset, static_cast<int>(n - offset));
                if (sent <= 0) return false;
                offset += sent;
            }
        }
    }
    return n >= 0;
}
struct EchoServer {
    struct Stream {
        int id;
        u32 len;
        bool end;
        bool response_hold_open;
        bool response_retryable;
        bool trailer;
        bool saw_grpc_content_type;
        bool saw_te_trailers;
        u8 te_count;
        bool saw_text_test_marker;
        u8 content_length_count;
        u32 content_length_value;
        u64 request_hash;
        u32 received_len;
        u8 data[256 * 1024];
    } streams[64]{};
    int listen_fd = -1;
    int fd = -1;
    pthread_t thread{};
    std::atomic<bool> stop{false};
    std::atomic<u32> requests{0};
    std::atomic<u32> resets{0};
    std::atomic<u32> accepts{0};
    std::atomic<u32> reply_mode{0};
    std::atomic<u32> stream_response_len{0};
    std::atomic<bool> stream_response_partial_next{false};
    std::atomic<bool> json_response{false};
    std::atomic<u32> duplicate_content_type_order{0};
    std::atomic<u32> request_trailers{0};
    std::atomic<u32> grpc_content_type_requests{0};
    std::atomic<u32> grpc_encoding_requests{0};
    std::atomic<u32> grpc_timeout_requests{0};
    std::atomic<u64> last_grpc_timeout_us{0};
    std::atomic<u32> te_trailers_requests{0};
    std::atomic<u32> bad_web_request_headers{0};
    std::atomic<u32> text_marker_requests{0};
    std::atomic<u32> text_content_length_requests{0};
    std::atomic<u32> window_updates{0};
    std::atomic<u32> last_completed_request_size{0};
    std::atomic<u32> last_completed_content_length{0};
    std::atomic<u64> last_completed_request_hash{0};
    bool started = false;
    TlsServerContext* tls_context = nullptr;
    std::atomic<u32> handshake_failures{0};
    std::atomic<bool> saw_sni{false};
    std::atomic<bool> saw_client_cert{false};
    std::atomic<u32> bad_schemes{0};
    Stream* get(int id) {
        for (auto& s : streams)
            if (s.id == id) return &s;
        for (auto& s : streams)
            if (!s.id) {
                s.id = id;
                s.request_hash = 14695981039346656037ull;
                return &s;
            }
        return nullptr;
    }
    static ssize_t read_data(nghttp2_session* session,
                             int32_t id,
                             uint8_t* buf,
                             size_t len,
                             uint32_t* flags,
                             nghttp2_data_source* source,
                             void*) {
        auto* s = static_cast<Stream*>(source->ptr);
        const u32 n = s->len < len ? s->len : static_cast<u32>(len);
        if (!n && (!s->end || s->response_hold_open)) return NGHTTP2_ERR_DEFERRED;
        memcpy(buf, s->data, n);
        s->len -= n;
        memmove(s->data, s->data + n, s->len);
        if (!s->len && s->end && !s->response_hold_open) {
            *flags |= NGHTTP2_DATA_FLAG_EOF | NGHTTP2_DATA_FLAG_NO_END_STREAM;
            nghttp2_nv trailers[] = {nv("grpc-status", s->response_retryable ? "7" : "0"),
                                     nv("x-trailer", "present")};
            if (nghttp2_submit_trailer(session, id, trailers, 2) != 0)
                return NGHTTP2_ERR_CALLBACK_FAILURE;
            s->trailer = true;
        }
        return n;
    }
    static int frame(nghttp2_session* session, const nghttp2_frame* f, void* user) {
        auto* self = static_cast<EchoServer*>(user);
        if (f->hd.type == NGHTTP2_WINDOW_UPDATE) self->window_updates++;
        if (!f->hd.stream_id) return 0;
        auto* s = self->get(f->hd.stream_id);
        if (!s) return NGHTTP2_ERR_CALLBACK_FAILURE;
        if (f->hd.type == NGHTTP2_HEADERS && f->headers.cat == NGHTTP2_HCAT_REQUEST) {
            self->requests++;
            if (s->saw_text_test_marker) {
                self->text_marker_requests++;
                if (s->content_length_count) self->text_content_length_requests++;
            }
            if (s->saw_grpc_content_type && (!s->saw_te_trailers || s->te_count != 1))
                self->bad_web_request_headers++;
            const u32 mode = self->reply_mode.exchange(0);
            if (mode == 2) return NGHTTP2_ERR_CALLBACK_FAILURE;
            if (mode == 6) return 0;
            if (mode == 7) self->json_response = true;
            if (mode == 8) self->duplicate_content_type_order = 1;
            if (mode == 9) self->duplicate_content_type_order = 2;
            if (mode == 5) {
                s->response_hold_open = true;
                const u32 message_len = self->stream_response_len.load();
                if (message_len < 5 || message_len > sizeof(s->data))
                    return NGHTTP2_ERR_CALLBACK_FAILURE;
                s->data[0] = 0;
                const u32 payload_len = message_len - 5;
                s->data[1] = static_cast<u8>(payload_len >> 24);
                s->data[2] = static_cast<u8>(payload_len >> 16);
                s->data[3] = static_cast<u8>(payload_len >> 8);
                s->data[4] = static_cast<u8>(payload_len);
                for (u32 i = 5; i < message_len; i++) s->data[i] = static_cast<u8>(0xa0 + i);
                s->len = message_len;
                if (self->stream_response_partial_next.load()) s->data[s->len++] = 0;
            }
            if (mode == 12) s->response_retryable = true;
            if (mode == 1) {
                nghttp2_nv error[] = {nv(":status", "200"),
                                      nv("content-type", "application/grpc"),
                                      nv("grpc-status", "7"),
                                      nv("grpc-message", "denied")};
                return nghttp2_submit_response(session, s->id, error, 4, nullptr);
            }
            if (mode == 10)
                return nghttp2_submit_rst_stream(
                    session, NGHTTP2_FLAG_NONE, s->id, NGHTTP2_REFUSED_STREAM);
            if (mode == 3) {
                static char large_value[12000];
                static bool initialized = false;
                if (!initialized) {
                    for (u32 i = 0; i < sizeof(large_value); i++)
                        large_value[i] = static_cast<char>('!' + ((i * 37u) % 94u));
                    initialized = true;
                }
                nghttp2_nv large[] = {nv(":status", "200"),
                                      nv("content-type", "application/grpc"),
                                      nv("grpc-status", "0"),
                                      {reinterpret_cast<uint8_t*>(const_cast<char*>("x-large")),
                                       reinterpret_cast<uint8_t*>(large_value),
                                       7,
                                       sizeof(large_value),
                                       NGHTTP2_NV_FLAG_NONE}};
                return nghttp2_submit_response(session, s->id, large, 4, nullptr);
            }
            if (mode == 4) nghttp2_submit_goaway(session, 0, s->id, NGHTTP2_NO_ERROR, nullptr, 0);
            const u32 duplicate_ct = self->duplicate_content_type_order.load();
            nghttp2_nv headers[4];
            headers[0] = nv(":status", "200");
            u32 header_count = 0;
            if (duplicate_ct) {
                headers[1] = duplicate_ct == 2 ? nv("content-type", "application/grpc+json")
                                               : nv("content-type", "application/grpc");
                headers[2] = duplicate_ct == 1 ? nv("content-type", "application/grpc+json")
                                               : nv("content-type", "application/grpc");
                headers[3] = nv("x-meta-bin", "AAEC/w==");
                header_count = 4;
            } else {
                headers[1] = self->json_response.load()
                                 ? nv("content-type", "application/grpc+json")
                                 : nv("content-type", "application/grpc");
                headers[2] = nv("x-meta-bin", "AAEC/w==");
                header_count = 3;
            }
            nghttp2_data_provider provider{};
            provider.source.ptr = s;
            provider.read_callback = &read_data;
            if (nghttp2_submit_response(session, s->id, headers, header_count, &provider) != 0)
                return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        if (f->hd.type == NGHTTP2_RST_STREAM) self->resets++;
        if (f->hd.type == NGHTTP2_HEADERS && f->headers.cat == NGHTTP2_HCAT_HEADERS)
            self->request_trailers++;
        if ((f->hd.type == NGHTTP2_HEADERS || f->hd.type == NGHTTP2_DATA) &&
            (f->hd.flags & NGHTTP2_FLAG_END_STREAM)) {
            s->end = true;
            self->last_completed_request_size = s->received_len;
            self->last_completed_content_length = s->content_length_value;
            self->last_completed_request_hash = s->request_hash;
            nghttp2_session_resume_data(session, s->id);
        }
        return 0;
    }
    static int header(nghttp2_session*,
                      const nghttp2_frame* frame,
                      const uint8_t* name,
                      size_t name_len,
                      const uint8_t* value,
                      size_t value_len,
                      uint8_t,
                      void* user) {
        auto* server = static_cast<EchoServer*>(user);
        auto* stream = frame && frame->hd.stream_id ? server->get(frame->hd.stream_id) : nullptr;
        if (stream && name_len == 12 && memcmp(name, "content-type", 12) == 0 && value_len == 16 &&
            memcmp(value, "application/grpc", 16) == 0) {
            stream->saw_grpc_content_type = true;
            server->grpc_content_type_requests++;
        }
        if (name_len == 13 && memcmp(name, "grpc-encoding", 13) == 0 && value_len == 4 &&
            memcmp(value, "gzip", 4) == 0)
            server->grpc_encoding_requests++;
        if (name_len == 12 && memcmp(name, "grpc-timeout", 12) == 0) {
            u64 timeout_us = 0;
            if (grpc_timeout({reinterpret_cast<const char*>(value), static_cast<u32>(value_len)},
                             &timeout_us)) {
                server->grpc_timeout_requests++;
                server->last_grpc_timeout_us.store(timeout_us);
            }
        }
        if (stream && name_len == 2 && memcmp(name, "te", 2) == 0 && value_len == 8 &&
            memcmp(value, "trailers", 8) == 0) {
            stream->saw_te_trailers = true;
            stream->te_count++;
            server->te_trailers_requests++;
        }
        if (stream && name_len == 15 && memcmp(name, "x-test-web-mode", 15) == 0 &&
            value_len == 4 && memcmp(value, "text", 4) == 0)
            stream->saw_text_test_marker = true;
        if (stream && name_len == 14 && memcmp(name, "content-length", 14) == 0) {
            stream->content_length_count++;
            u32 parsed = 0;
            for (size_t i = 0; i < value_len; i++) {
                if (value[i] < '0' || value[i] > '9' || parsed > (0xffffffffu / 10)) return 0;
                parsed = parsed * 10 + value[i] - '0';
            }
            stream->content_length_value = parsed;
        }
        if (name_len != 7 || memcmp(name, ":scheme", 7) != 0) return 0;
        const char* expected = server->tls_context ? "https" : "http";
        if (value_len != strlen(expected) || memcmp(value, expected, value_len) != 0)
            server->bad_schemes++;
        return 0;
    }
    static int data(nghttp2_session* session,
                    uint8_t,
                    int32_t id,
                    const uint8_t* data,
                    size_t len,
                    void* user) {
        auto* s = static_cast<EchoServer*>(user)->get(id);
        if (!s || len > sizeof(s->data) - s->len) return NGHTTP2_ERR_CALLBACK_FAILURE;
        memcpy(s->data + s->len, data, len);
        s->received_len += static_cast<u32>(len);
        for (size_t i = 0; i < len; i++) {
            s->request_hash ^= data[i];
            s->request_hash *= 1099511628211ull;
        }
        s->len += static_cast<u32>(len);
        nghttp2_session_resume_data(session, id);
        return 0;
    }
    static void* run(void* ptr) {
        auto* self = static_cast<EchoServer*>(ptr);
        while (!self->stop.load()) {
            pollfd p{self->listen_fd, POLLIN, 0};
            if (poll(&p, 1, 20) <= 0) continue;
            self->fd = accept(self->listen_fd, nullptr, nullptr);
            if (self->fd < 0) continue;
            self->accepts++;
            for (auto& stream : self->streams) stream = {};
            set_socket_timeouts(self->fd, 2);
            SSL* ssl = nullptr;
            if (self->tls_context) {
                auto created = create_tls_server_ssl(self->tls_context, self->fd);
                if (created) ssl = created.value();
                if (!ssl || SSL_accept(ssl) != 1) {
                    self->handshake_failures++;
                    if (ssl) SSL_free(ssl);
                    close(self->fd);
                    self->fd = -1;
                    continue;
                }
                const char* name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
                self->saw_sni = name && strcmp(name, "localhost") == 0;
                X509* peer = SSL_get1_peer_certificate(ssl);
                self->saw_client_cert = peer != nullptr;
                if (peer) X509_free(peer);
            }
            nghttp2_session_callbacks* cb;
            nghttp2_session_callbacks_new(&cb);
            nghttp2_session_callbacks_set_on_frame_recv_callback(cb, &frame);
            nghttp2_session_callbacks_set_on_header_callback(cb, &header);
            nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cb, &data);
            nghttp2_session* session;
            nghttp2_session_server_new(&session, cb, self);
            nghttp2_session_callbacks_del(cb);
            nghttp2_submit_settings(session, 0, nullptr, 0);
            flush_session(session, self->fd, ssl);
            while (!self->stop.load()) {
                pollfd r{self->fd, POLLIN, 0};
                if ((!ssl || !SSL_has_pending(ssl)) && poll(&r, 1, 20) <= 0) continue;
                u8 bytes[16384];
                const ssize_t n = ssl ? SSL_read(ssl, bytes, sizeof(bytes))
                                      : recv(self->fd, bytes, sizeof(bytes), 0);
                if (n <= 0 || nghttp2_session_mem_recv(session, bytes, n) != n ||
                    !flush_session(session, self->fd, ssl))
                    break;
            }
            nghttp2_session_del(session);
            if (ssl) SSL_free(ssl);
            close(self->fd);
            self->fd = -1;
        }
        return nullptr;
    }
    bool start(bool tls = false, bool mutual = false, bool h2 = true, u16 port = 0) {
        if (tls) {
            auto context = create_tls_server_context(RUT_GRPC_FIXTURES "/localhost_cert.pem",
                                                     RUT_GRPC_FIXTURES "/localhost_key.pem",
                                                     h2);
            if (!context) return false;
            tls_context = context.value();
            if (mutual) {
                if (SSL_CTX_load_verify_locations(tls_context->ssl_ctx,
                                                  RUT_GRPC_FIXTURES "/localhost_cert.pem",
                                                  nullptr) != 1)
                    return false;
                SSL_CTX_set_verify(tls_context->ssl_ctx,
                                   SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                                   nullptr);
            }
        }
        listen_fd = create_listen_socket(port).value_or(-1);
        if (listen_fd < 0) return false;
        started = pthread_create(&thread, nullptr, &run, this) == 0;
        return started;
    }
    ~EchoServer() {
        stop = true;
        if (started) pthread_join(thread, nullptr);
        if (listen_fd >= 0) close(listen_fd);
        destroy_tls_server_context(tls_context);
    }
};
struct Client {
    SSL_CTX* tls_context = nullptr;
    SSL* ssl = nullptr;
    struct Rpc {
        static constexpr u32 kWebBufferCap = 262144;
        u32 sent = 0, received = 0, size = 0;
        u32 status = 99, http_status = 0;
        bool status_in_trailers = false;
        u32 raw_len = 0, max_chunk = 0, response_len = 0;
        bool request_trailer = false, end = true, response_end = false, closed = false, ok = false,
             meta = false, trailer = false, raw_request = false, compare_pattern = true,
             web_content_type = false;
        std::unique_ptr<u8[]> raw;
        std::unique_ptr<u8[]> response;
    } rpcs[17];
    nghttp2_session* session = nullptr;
    bool goaway = false;
    u32 window_updates = 0;
    int fd = -1;
    static u8 byte_at(u32 i) { return static_cast<u8>((i * 17 + i / 256) & 255); }
    static ssize_t data(nghttp2_session* session,
                        int32_t sid,
                        uint8_t* out,
                        size_t cap,
                        uint32_t* flags,
                        nghttp2_data_source* source,
                        void*) {
        auto* rpc = static_cast<Rpc*>(source->ptr);
        u32 n = rpc->raw_request ? rpc->raw_len - rpc->sent : rpc->size - rpc->sent;
        if (n > cap) n = static_cast<u32>(cap);
        if (rpc->max_chunk && n > rpc->max_chunk) n = rpc->max_chunk;
        if (!n && !rpc->end) return NGHTTP2_ERR_DEFERRED;
        if (rpc->raw_request)
            memcpy(out, rpc->raw.get() + rpc->sent, n);
        else
            for (u32 i = 0; i < n; i++) out[i] = byte_at(rpc->sent + i);
        rpc->sent += n;
        if (rpc->sent == (rpc->raw_request ? rpc->raw_len : rpc->size) && rpc->end) {
            *flags |= NGHTTP2_DATA_FLAG_EOF;
            if (rpc->request_trailer) {
                *flags |= NGHTTP2_DATA_FLAG_NO_END_STREAM;
                nghttp2_nv trailer[] = {nv("x-request-end", "present")};
                if (nghttp2_submit_trailer(session, sid, trailer, 1) != 0)
                    return NGHTTP2_ERR_CALLBACK_FAILURE;
            }
        }
        return n;
    }
    static int receive(
        nghttp2_session*, uint8_t, int32_t sid, const uint8_t* data, size_t len, void* ctx) {
        auto& rpc = static_cast<Client*>(ctx)->rpcs[(sid - 1) / 2];
        if (rpc.compare_pattern) {
            for (u32 i = 0; i < len; i++)
                if (data[i] != byte_at(rpc.received + i)) return NGHTTP2_ERR_CALLBACK_FAILURE;
        } else if (len > Rpc::kWebBufferCap - rpc.response_len) {
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        } else {
            if (!rpc.response) rpc.response = std::make_unique<u8[]>(Rpc::kWebBufferCap);
            memcpy(rpc.response.get() + rpc.response_len, data, len);
            rpc.response_len += static_cast<u32>(len);
        }
        rpc.received += static_cast<u32>(len);
        return 0;
    }
    static int header(nghttp2_session*,
                      const nghttp2_frame* f,
                      const uint8_t* name,
                      size_t n,
                      const uint8_t* value,
                      size_t v,
                      uint8_t,
                      void* ctx) {
        auto& rpc = static_cast<Client*>(ctx)->rpcs[(f->hd.stream_id - 1) / 2];
        if (n == 7 && memcmp(name, ":status", n) == 0) {
            rpc.http_status = 0;
            for (size_t i = 0; i < v; ++i) rpc.http_status = rpc.http_status * 10 + value[i] - '0';
        }
        if (n == 11 && memcmp(name, "grpc-status", n) == 0) {
            rpc.ok = v == 1 && *value == '0';
            rpc.status_in_trailers = (f->hd.flags & NGHTTP2_FLAG_END_STREAM) != 0;
            rpc.status = 0;
            for (size_t i = 0; i < v; i++) rpc.status = rpc.status * 10 + value[i] - '0';
        }
        if (n == 10 && memcmp(name, "x-meta-bin", n) == 0)
            rpc.meta = v == 8 && memcmp(value, "AAEC/w==", 8) == 0;
        if (n == 9 && memcmp(name, "x-trailer", n) == 0)
            rpc.trailer = v == 7 && memcmp(value, "present", 7) == 0;
        if (n == 12 && memcmp(name, "content-type", n) == 0)
            rpc.web_content_type = (v >= 20 && memcmp(value, "application/grpc-web", 20) == 0);
        return 0;
    }
    static int frame(nghttp2_session*, const nghttp2_frame* f, void* ctx) {
        if (f->hd.type == NGHTTP2_GOAWAY) static_cast<Client*>(ctx)->goaway = true;
        if ((f->hd.type == NGHTTP2_HEADERS || f->hd.type == NGHTTP2_DATA) &&
            (f->hd.flags & NGHTTP2_FLAG_END_STREAM))
            static_cast<Client*>(ctx)->rpcs[(f->hd.stream_id - 1) / 2].response_end = true;
        return 0;
    }
    static int frame_send(nghttp2_session*, const nghttp2_frame* f, void* ctx) {
        if (f->hd.type == NGHTTP2_WINDOW_UPDATE) static_cast<Client*>(ctx)->window_updates++;
        return 0;
    }
    static int closed(nghttp2_session*, int32_t sid, uint32_t, void* ctx) {
        static_cast<Client*>(ctx)->rpcs[(sid - 1) / 2].closed = true;
        return 0;
    }
    bool init(u16 port, bool tls = false) {
        fd = connect_to(port);
        if (fd < 0) return false;
        set_socket_timeouts(fd, 5);
        if (tls) {
            tls_context = SSL_CTX_new(TLS_client_method());
            if (!tls_context) return false;
            ssl = SSL_new(tls_context);
            const u8 alpn[] = {2, 'h', '2'};
            if (!ssl || !SSL_set_fd(ssl, fd) || SSL_set_alpn_protos(ssl, alpn, sizeof(alpn)) != 0 ||
                SSL_connect(ssl) != 1)
                return false;
        }
        nghttp2_session_callbacks* cb;
        nghttp2_session_callbacks_new(&cb);
        nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cb, &receive);
        nghttp2_session_callbacks_set_on_header_callback(cb, &header);
        nghttp2_session_callbacks_set_on_stream_close_callback(cb, &closed);
        nghttp2_session_callbacks_set_on_frame_recv_callback(cb, &frame);
        nghttp2_session_callbacks_set_on_frame_send_callback(cb, &frame_send);
        const int rc = nghttp2_session_client_new(&session, cb, this);
        nghttp2_session_callbacks_del(cb);
        nghttp2_submit_settings(session, 0, nullptr, 0);
        return rc == 0;
    }
    int request(u32 index,
                u32 bytes,
                bool end,
                const char* timeout = nullptr,
                bool jit_forward = false,
                bool jit_timer_forward = false) {
        rpcs[index].size = bytes;
        rpcs[index].end = end;
        static thread_local char content_length[16];
        nghttp2_nv headers[8] = {nv(":method", "POST"),
                                 nv(":scheme", "http"),
                                 nv(":authority", "grpc.test"),
                                 nv(":path",
                                    jit_timer_forward ? "/jitwait.Echo/Call"
                                    : jit_forward     ? "/jit.Echo/Call"
                                                      : "/test.Echo/Call"),
                                 nv("content-type", "application/grpc+proto"),
                                 nv("te", "trailers"),
                                 nv("grpc-timeout", timeout ? timeout : "1H")};
        if (jit_forward) {
            snprintf(content_length, sizeof(content_length), "%u", bytes);
            headers[7] = nv("content-length", content_length);
        }
        nghttp2_data_provider provider{};
        provider.source.ptr = &rpcs[index];
        provider.read_callback = &data;
        return nghttp2_submit_request(session, nullptr, headers, 7, &provider, nullptr);
    }
    int request_native_raw(u32 index,
                           const u8* body,
                           u32 body_len,
                           const char* timeout = "1H",
                           const char* encoding = nullptr,
                           const char* path = "/test.Echo/Call",
                           const char* content_type = "application/grpc+proto") {
        auto& rpc = rpcs[index];
        if (body_len > Rpc::kWebBufferCap) return -1;
        if (!rpc.raw) rpc.raw = std::make_unique<u8[]>(Rpc::kWebBufferCap);
        memcpy(rpc.raw.get(), body, body_len);
        rpc.raw_len = body_len;
        rpc.raw_request = true;
        rpc.compare_pattern = false;
        rpc.end = true;
        nghttp2_nv headers[8] = {nv(":method", "POST"),
                                 nv(":scheme", "http"),
                                 nv(":authority", "grpc.test"),
                                 nv(":path", path),
                                 nv("content-type", content_type),
                                 nv("te", "trailers"),
                                 nv("grpc-timeout", timeout)};
        if (encoding) headers[7] = nv("grpc-encoding", encoding);
        nghttp2_data_provider provider{};
        provider.source.ptr = &rpc;
        provider.read_callback = &data;
        return nghttp2_submit_request(
            session, nullptr, headers, encoding ? 8 : 7, &provider, nullptr);
    }
    int request_web(u32 index,
                    const u8* body,
                    u32 body_len,
                    bool text,
                    u32 chunk,
                    bool content_length = false,
                    const char* timeout = "1H") {
        auto& rpc = rpcs[index];
        if (body_len > Rpc::kWebBufferCap) return -1;
        if (!rpc.raw) rpc.raw = std::make_unique<u8[]>(Rpc::kWebBufferCap);
        memcpy(rpc.raw.get(), body, body_len);
        rpc.raw_len = body_len;
        rpc.raw_request = true;
        rpc.compare_pattern = false;
        rpc.end = true;
        rpc.max_chunk = chunk;
        static thread_local char content_length_value[16];
        nghttp2_nv headers[8] = {
            nv(":method", "POST"),
            nv(":scheme", "http"),
            nv(":authority", "grpc.test"),
            nv(":path", "/test.Echo/Call"),
            nv("content-type", text ? "application/grpc-web-text" : "application/grpc-web"),
            nv("grpc-timeout", timeout)};
        size_t count = 6;
        if (text) headers[count++] = nv("x-test-web-mode", "text");
        if (content_length) {
            snprintf(content_length_value, sizeof(content_length_value), "%u", body_len);
            headers[count++] = nv("content-length", content_length_value);
        }
        nghttp2_data_provider provider{};
        provider.source.ptr = &rpc;
        provider.read_callback = &data;
        return nghttp2_submit_request(session, nullptr, headers, count, &provider, nullptr);
    }
    bool step() {
        if (!flush_session(session, fd, ssl)) return false;
        pollfd p{fd, POLLIN, 0};
        const int ready = ssl && SSL_pending(ssl) ? 1 : poll(&p, 1, 100);
        if (ready == 0) return true;
        if (ready < 0) return errno == EINTR;
        u8 bytes[32768];
        const i32 n = ssl ? SSL_read(ssl, bytes, sizeof(bytes))
                          : recv_timeout(fd, reinterpret_cast<char*>(bytes), sizeof(bytes), 1000);
        const ssize_t processed = n > 0 ? nghttp2_session_mem_recv(session, bytes, n) : -999;
        if (!(n > 0 && processed == n))
            fprintf(stderr,
                    "step n=%d processed=%zd tls_error=%d errno=%d\n",
                    n,
                    processed,
                    ssl ? SSL_get_error(ssl, n) : 0,
                    errno);
        return n > 0 && processed == n;
    }
    bool until(u32 index, bool complete) {
        const u64 deadline = monotonic_us() + 5000000;
        while (monotonic_us() < deadline) {
            const auto& rpc = rpcs[index];
            if (complete ? rpc.response_end : rpc.received == rpc.size) return true;
            if (!step()) {
                fprintf(stderr,
                        "rpc %u failed: received=%u status=%u end=%d goaway=%d\n",
                        index,
                        rpc.received,
                        rpc.status,
                        rpc.response_end,
                        goaway);
                return false;
            }
        }
        fprintf(stderr, "rpc %u timed out\n", index);
        return false;
    }
    ~Client() {
        if (session) nghttp2_session_del(session);
        if (ssl) SSL_free(ssl);
        if (tls_context) SSL_CTX_free(tls_context);
        if (fd >= 0) close(fd);
    }
};

template <typename Loop>
void streaming_case(rut::test::TestCase* _tc,
                    bool tls = false,
                    bool upstream_tls = false,
                    bool mutual = false,
                    bool large_first = false) {
    auto server = std::make_unique<EchoServer>();
    REQUIRE(server->start(upstream_tls, mutual));
    auto shard = std::make_unique<Shard<Loop>>();
    const int lfd = create_listen_socket(0).value_or(-1);
    REQUIRE(lfd >= 0);
    if (!shard->init(0, lfd).has_value()) {
        close(lfd);
        SKIP("backend unavailable");
    }
    REQUIRE(shard->init_access_log().has_value());
    RouteConfig cfg;
    REQUIRE(cfg.add_upstream("grpc", 0x7f000001, get_port(server->listen_fd)).has_value());
    cfg.upstreams[0].http2 = true;
    CHECK_EQ(cfg.upstreams[0].addr_count, 1u);
    if (upstream_tls) {
        auto& spec = cfg.upstreams[0].tls;
        spec.enabled = true;
        strcpy(spec.ca, RUT_GRPC_FIXTURES "/localhost_cert.pem");
        strcpy(spec.server_name, "localhost");
        if (mutual) {
            strcpy(spec.cert, RUT_GRPC_FIXTURES "/localhost_cert.pem");
            strcpy(spec.key, RUT_GRPC_FIXTURES "/localhost_key.pem");
        }
    }
    REQUIRE(cfg.add_proxy("/test.Echo/", 'P', 0));
    REQUIRE(cfg.add_jit_handler("/jit.Echo/", 'P', &grpc_jit_forward, false));
    REQUIRE(cfg.add_jit_handler("/jitwait.Echo/", 'P', &grpc_jit_timer_forward, false));
    shard->route_config = &cfg;
#if RUT_GRPC_JIT
    struct Program {
        LoadedProgram program;
        ~Program() { program.destroy(); }
    };
    auto compiled = std::make_unique<Program>();
    if (tls || upstream_tls) {
        char path[] = "/tmp/rut-grpc-XXXXXX";
        const int file = mkstemp(path);
        REQUIRE(file >= 0);
        char source[2048];
        char tls_fields[1024]{};
        if (upstream_tls) {
            snprintf(tls_fields,
                     sizeof(tls_fields),
                     ", tls: { ca: \"%s\", server_name: \"localhost\"%s }",
                     RUT_GRPC_FIXTURES "/localhost_cert.pem",
                     mutual ? ", cert: \"" RUT_GRPC_FIXTURES
                              "/localhost_cert.pem\", key: \"" RUT_GRPC_FIXTURES
                              "/localhost_key.pem\""
                            : "");
        }
        const int len =
            snprintf(source,
                     sizeof(source),
                     "upstream grpc { host: \"127.0.0.1\", port: %u, protocol: .http2%s }\n"
                     "route POST \"/test.Echo/Call\" { return forward(grpc) }\n"
                     "route POST \"/jit.Echo/Call\" { return forward(grpc) }\n"
                     "route POST \"/jitwait.Echo/Call\" { wait(100) return forward(grpc) }\n",
                     get_port(server->listen_fd),
                     tls_fields);
        const bool written = write(file, source, len) == len;
        close(file);
        LoadError error;
        const bool loaded = written && load_rut_program(path, compiled->program, error);
        unlink(path);
        REQUIRE(loaded);
        CHECK(compiled->program.config.upstreams[0].http2);
        shard->route_config = &compiled->program.config;
    }
#endif
    TlsServerContext* tls_server = nullptr;
    if (tls) {
        auto context = create_tls_server_context(
            RUT_GRPC_FIXTURES "/localhost_cert.pem", RUT_GRPC_FIXTURES "/localhost_key.pem", true);
        REQUIRE(context);
        tls_server = context.value();
        shard->loop->tls_server = tls_server;
    }
    REQUIRE(shard->spawn(-1).has_value());
    // No REQUIRE after spawning: always stop/join before destroying config.
    {
        Client a, b;
        const bool connected = a.init(get_port(lfd), tls) && b.init(get_port(lfd), tls);
        CHECK(connected);
        if (connected) {
            CHECK_EQ(a.request(0, large_first ? 200000 : 128, false), 1);
            const bool echoed = a.until(0, false);
            CHECK(echoed);  // response DATA arrives before request END_STREAM
            if (echoed) {
                const u32 resets_before_completed_rpc = server->resets.load();
                CHECK_EQ(a.request(1, 200000, true), 3);
                CHECK(a.until(1, true));  // multiplex while stream 1 stays open
                CHECK(a.rpcs[1].ok && a.rpcs[1].meta && a.rpcs[1].trailer);
                CHECK_EQ(a.rpcs[1].received, 200000u);
                CHECK_EQ(server->resets.load(), resets_before_completed_rpc);
                CHECK_EQ(b.request(0, 64, true), 1);
                CHECK(b.until(0, true));  // a second downstream shares the same upstream
                CHECK(b.rpcs[0].ok);
                a.rpcs[0].size = large_first ? 300000 : 100000;
                a.rpcs[0].end = true;
                CHECK_EQ(nghttp2_session_resume_data(a.session, 1), 0);
                CHECK(a.until(0, true));
                CHECK(a.rpcs[0].ok && a.rpcs[0].trailer);
                CHECK_EQ(a.rpcs[0].received, large_first ? 300000u : 100000u);
                CHECK_EQ(server->accepts.load(), 1u);
                CHECK_EQ(server->requests.load(), 3u);
                CHECK_EQ(a.request(2, 32, false), 5);
                CHECK(a.until(2, false));
                CHECK_EQ(nghttp2_submit_rst_stream(a.session, 0, 5, NGHTTP2_CANCEL), 0);
                CHECK(flush_session(a.session, a.fd, a.ssl));
                const u64 deadline_start = monotonic_us();
                CHECK_EQ(a.request(3, 32, false, "100m"), 7);
                CHECK(a.until(3, true));
                CHECK(monotonic_us() - deadline_start < 900000u);
                CHECK_EQ(a.rpcs[3].status, 4u);
                a.rpcs[4].request_trailer = true;
                CHECK_EQ(a.request(4, 160000, true), 9);
                CHECK(a.until(4, true));
                CHECK(a.rpcs[4].ok);
                CHECK_EQ(a.rpcs[4].received, 160000u);
                CHECK(server->resets.load() >= 2u);
                CHECK_EQ(server->accepts.load(), 1u);
                CHECK_EQ(server->request_trailers.load(), 1u);
                server->reply_mode = 1;
                CHECK_EQ(a.request(5, 0, true), 11);
                CHECK(a.until(5, true));
                CHECK_EQ(a.rpcs[5].status, 7u);
                server->reply_mode = 2;
                CHECK_EQ(a.request(6, 0, true), 13);
                CHECK(a.until(6, true));
                CHECK_EQ(a.rpcs[6].status, 14u);
                CHECK_EQ(a.request(7, 1024, true), 15);
                CHECK(a.until(7, true));
                CHECK(a.rpcs[7].ok);
                CHECK_EQ(server->accepts.load(), 2u);
                server->reply_mode = 4;
                CHECK_EQ(a.request(8, 1024, true), 17);
                CHECK(a.until(8, true));
                CHECK(a.rpcs[8].ok);
                CHECK_EQ(a.request(9, 1024, true), 19);
                CHECK(a.until(9, true));
                CHECK(a.rpcs[9].ok);
                CHECK_EQ(server->accepts.load(), 3u);
                // A response with no stream window must not block another client.
                nghttp2_settings_entry window{NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 0};
                CHECK_EQ(nghttp2_submit_settings(a.session, 0, &window, 1), 0);
                CHECK_EQ(a.request(10, 8192, true), 21);
                const u64 stall_deadline = monotonic_us() + 1000000;
                while (!a.rpcs[10].meta && monotonic_us() < stall_deadline) {
                    if (!a.step()) break;
                }
                CHECK(a.rpcs[10].meta);
                CHECK_EQ(a.rpcs[10].received, 0u);
                CHECK_EQ(b.request(1, 2048, true), 3);
                CHECK(b.until(1, true));
                CHECK(b.rpcs[1].ok);
                window.value = 65535;
                CHECK_EQ(nghttp2_submit_settings(a.session, 0, &window, 1), 0);
                CHECK(a.until(10, true));
                CHECK(a.rpcs[10].ok);
                CHECK_EQ(a.rpcs[10].received, 8192u);
                // A successful early response must cancel the still-open
                // upstream request stream so the server does not retain it.
                server->reply_mode = 1;
                const u32 resets_before_early_response = server->resets.load();
                CHECK_EQ(a.request(11, 1024, false), 23);
                CHECK(a.until(11, true));
                const u64 reset_deadline = monotonic_us() + 500000;
                while (server->resets.load() < resets_before_early_response + 1 &&
                       monotonic_us() < reset_deadline)
                    CHECK(a.step());
                CHECK_EQ(server->resets.load(), resets_before_early_response + 1);
                server->reply_mode = 3;
                CHECK_EQ(a.request(12, 0, true), 25);
                CHECK(a.until(12, true));
                CHECK(a.rpcs[12].ok);
                // A client disconnect retires its open RPC as CANCELLED.
                {
                    Client disconnected;
                    CHECK(disconnected.init(get_port(lfd), tls));
                    CHECK_EQ(disconnected.request(0, 32, false), 1);
                    CHECK(disconnected.until(0, false));
                }
                // Draining sends GOAWAY but lets a bidirectional RPC finish.
                CHECK_EQ(a.request(13, 4096, true, nullptr, true), 27);
                CHECK(a.until(13, true));
                CHECK(a.rpcs[13].ok);
                CHECK_EQ(a.rpcs[13].received, 4096u);
                CHECK_EQ(a.request(14, 0, true, nullptr, true, true), 29);
                CHECK(a.until(14, true));
                CHECK(a.rpcs[14].ok);
                CHECK_EQ(a.request(15, 128, false, nullptr, true, true), 31);
                CHECK(a.until(15, false));
                a.rpcs[15].size = 128;
                a.rpcs[15].end = true;
                CHECK_EQ(nghttp2_session_resume_data(a.session, 31), 0);
                CHECK(a.until(15, true));
                CHECK(a.rpcs[15].ok);
                CHECK_EQ(a.rpcs[15].received, 128u);
                CHECK_EQ(a.request(16, 128, false), 33);
                CHECK(a.until(16, false));
                shard->loop->drain(5);
                const u64 drain_deadline = monotonic_us() + 2500000;
                while (!a.goaway && monotonic_us() < drain_deadline) {
                    if (!a.step()) break;
                }
                CHECK(a.goaway);
                a.rpcs[16].size = 32768;
                a.rpcs[16].end = true;
                CHECK_EQ(nghttp2_session_resume_data(a.session, 33), 0);
                CHECK(a.until(16, true));
                CHECK(a.rpcs[16].ok);
                CHECK_EQ(a.rpcs[16].received, 32768u);
            }
        }
    }
    shard->stop();
    shard->join();
    CHECK_EQ(shard->shard_metrics.connections_total, 3u);
    shard->loop->force_close_all();
    CHECK_EQ(shard->shard_metrics.connections_active, 0u);
    CHECK_EQ(shard->shard_metrics.connections_closed, 3u);
    const auto& metrics = shard->shard_metrics;
    CHECK_EQ(metrics.grpc_started, 20u);
    CHECK_EQ(metrics.grpc_active, 0u);
    CHECK_EQ(metrics.grpc_completed[0], 14u);
    CHECK_EQ(metrics.grpc_completed[1], 2u);
    CHECK_EQ(metrics.grpc_completed[4], 1u);
    CHECK_EQ(metrics.grpc_completed[7], 2u);
    CHECK_EQ(metrics.grpc_completed[14], 1u);
    CHECK_EQ(metrics.grpc_latency.count, 20u);
    CHECK_EQ(server->bad_schemes.load(), 0u);
    if (upstream_tls) {
        CHECK(server->saw_sni.load());
        CHECK_EQ(server->saw_client_cert.load(), mutual);
    }
    AccessLogEntry entry;
    u32 logs = 0;
    u32 statuses[17]{};
    bool large_call = false;
    while (shard->log_ring->pop(entry)) {
        logs++;
        CHECK_EQ(entry.status, 200u);
        CHECK_EQ(entry.method, static_cast<u8>(LogHttpMethod::Post));
        CHECK_EQ(entry.target_state, AccessLogTargetState::Complete);
        const Str path{entry.path, entry.target_length};
        CHECK(path.eq(lit_str("/test.Echo/Call")) || path.eq(lit_str("/jit.Echo/Call")) ||
              path.eq(lit_str("/jitwait.Echo/Call")));
        CHECK(strcmp(entry.upstream, "grpc") == 0);
        CHECK(entry.grpc_status_plus_one >= 1 && entry.grpc_status_plus_one <= 17);
        if (entry.grpc_status_plus_one >= 1 && entry.grpc_status_plus_one <= 17)
            statuses[entry.grpc_status_plus_one - 1]++;
        if (entry.req_size == 200000 && entry.resp_size == 200000) large_call = true;
    }
    CHECK_EQ(logs, 20u);
    CHECK(large_call);
    for (u32 code = 0; code < 17; code++) CHECK_EQ(statuses[code], metrics.grpc_completed[code]);
    if (shard->loop->listen_fd >= 0) {
        close(shard->loop->listen_fd);
        shard->loop->listen_fd = -1;
    }
    shard->shutdown();
    if (tls_server) destroy_tls_server_context(tls_server);
}

struct GrpcDriveFixture {
    ShardMetrics* metrics = nullptr;
    AccessLogRing* access_log = nullptr;
    SourceLiveAccessLogProducer* live_access_log = nullptr;
    Connection* grpc_upstreams = nullptr;
    const RouteConfig** config_ptr = nullptr;
    TimerWheel timer;
    SlicePool pool;
    bool pool_ready = false;
    u32 keepalive_timeout = 60;
    u32 upstream_timeout = 1;
    u32 sends = 0;
    u32 last_send_len = 0;
    u32 fail_send_on = 0;
    u32 downstream_sends = 0;
    u32 downstream_last_send_len = 0;
    bool saw_downstream_stream3 = false;
    bool saw_window_update = false;
    u32 released = 0;
    bool closed = false;
    GrpcDriveFixture() {
        timer.init();
        pool_ready = pool.init(128, 0, SlicePool::kMaxCachedSlices, 8).has_value();
    }
    ~GrpcDriveFixture() {
        if (pool_ready) pool.destroy();
    }
    bool submit_send(Connection& conn, const u8* data, u32 len) {
        sends++;
        last_send_len = len;
        if (conn.h2 && !conn.h2->grpc.upstream) {
            downstream_sends++;
            downstream_last_send_len = len;
            for (u32 off = 0; off + kFrameHeaderSize <= len;) {
                const u32 frame_len = (static_cast<u32>(data[off]) << 16) |
                                      (static_cast<u32>(data[off + 1]) << 8) | data[off + 2];
                const u32 sid = (static_cast<u32>(data[off + 5]) << 24) |
                                (static_cast<u32>(data[off + 6]) << 16) |
                                (static_cast<u32>(data[off + 7]) << 8) | data[off + 8];
                if ((sid & 0x7fffffffu) == 3u) saw_downstream_stream3 = true;
                if (data[off + 3] == static_cast<u8>(Http2FrameType::WindowUpdate))
                    saw_window_update = true;
                if (off + kFrameHeaderSize + frame_len > len) break;
                off += kFrameHeaderSize + frame_len;
            }
        } else if (len >= kFrameHeaderSize &&
                   data[3] == static_cast<u8>(Http2FrameType::WindowUpdate)) {
            saw_window_update = true;
        }
        return fail_send_on == 0 || sends != fail_send_on;
    }
    bool submit_recv(Connection&) { return true; }
    bool submit_connect(Connection&, const void*, u32) { return true; }
    bool submit_send_upstream(Connection&, const u8*, u32) { return true; }
    bool submit_recv_upstream(Connection&) { return true; }
    bool arm_throttle_timer(Connection&, u64) { return false; }
    void disarm_yield_timer(Connection& conn) { conn.yield_armed = false; }
    bool alloc_upstream_buf(Connection&) { return true; }
    void clear_upstream_fd(u32) {}
    bool alloc_response_header_buf(Connection&) { return true; }
    bool schedule_yield_timer(Connection&, u32) { return true; }
    bool is_draining() const { return false; }
    void epoch_enter() {}
    void epoch_leave() {}
    void close_conn(Connection&) { closed = true; }
    bool upstream_acquire(u16, u32) { return true; }
    void upstream_release(u16) { released++; }
};
struct SyncCloseGrpcDriveFixture : GrpcDriveFixture {
    bool submit_send(Connection&, const u8*, u32) { return false; }
    void close_conn(Connection& conn) {
        if (conn.on_close) conn.on_close(this, conn);
        conn.on_close = nullptr;
        conn.h2 = nullptr;
        conn.handler_gen++;
        closed = true;
    }
};
struct SyncRetryBindCloseFixture : GrpcDriveFixture {
    Connection retry_conn;
    Http2Conn retry_h2;
    Connection* alloc_conn() {
        retry_conn.reset();
        return &retry_conn;
    }
    bool alloc_h2(Connection& conn) {
        retry_h2.init_client();
        conn.h2 = &retry_h2;
        return true;
    }
    bool submit_connect(Connection&, const void*, u32) { return false; }
    void close_conn(Connection& conn) {
        if (conn.on_close) conn.on_close(this, conn);
        if (conn.upstream_fd >= 0) close(conn.upstream_fd);
        conn.upstream_fd = conn.fd = -1;
        conn.on_close = nullptr;
        conn.h2 = nullptr;
        closed = true;
    }
};
struct RetrySelectionFixture : GrpcDriveFixture {
    Connection retry_conn;
    Http2Conn retry_h2;
    Connection* alloc_conn() {
        retry_conn.reset();
        return &retry_conn;
    }
    bool alloc_h2(Connection& conn) {
        retry_h2.init_client();
        conn.h2 = &retry_h2;
        return true;
    }
    bool submit_connect(Connection&, const void*, u32) { return true; }
};
struct RetryCloseGrpcDriveFixture : SyncCloseGrpcDriveFixture {
    bool arm_throttle_timer(Connection&, u64) { return true; }
};
struct RetryCloseSelectionFixture : RetryCloseGrpcDriveFixture {
    Connection retry_conn;
    Http2Conn retry_h2;
    Connection* alloc_conn() {
        retry_conn.reset();
        return &retry_conn;
    }
    bool alloc_h2(Connection& conn) {
        retry_h2.init_client();
        conn.h2 = &retry_h2;
        return true;
    }
    bool submit_connect(Connection&, const void*, u32) { return true; }
    void close_released_upstream(Connection& conn) {
        if (conn.upstream_fd >= 0) close(conn.upstream_fd);
        conn.upstream_fd = -1;
    }
};
struct GrpcConnectRetirementFixture : GrpcDriveFixture {
    const RouteConfig** config_ptr = nullptr;
    u32 connect_submissions = 0;
    bool submit_connect(Connection& conn, const void*, u32) {
        connect_submissions++;
        conn.upstream_connect_armed = true;
        conn.pending_ops = 1;
        return true;
    }
    void close_released_upstream(Connection& conn) {
        if (conn.upstream_fd >= 0) close(conn.upstream_fd);
        conn.upstream_fd = -1;
    }
    bool retire_pending_upstream_connect(Connection& conn) {
        if (!conn.upstream_connect_armed || conn.pending_ops != 1) return false;
        conn.upstream_retiring_episode = conn.upstream_episode;
        conn.upstream_episode++;
        conn.upstream_retirement_active = true;
        conn.upstream_retirement_target_owned = kUpstreamOpConnect;
        conn.upstream_retirement_cancel_owned = kUpstreamOpConnect;
        conn.upstream_connect_armed = false;
        conn.pending_ops = 2;
        return true;
    }
    void close_conn(Connection&) { closed = true; }
};
struct HeldSendGrpcDriveFixture : GrpcDriveFixture {
    CaptureRing* capture_ring = nullptr;
    const u8* pending_send = nullptr;
    u32 pending_send_len = 0;
    u32 epoch_enters = 0;
    u32 epoch_leaves = 0;
    void epoch_enter() { epoch_enters++; }
    void epoch_leave() { epoch_leaves++; }
    bool submit_send(Connection&, const u8* data, u32 len) {
        sends++;
        pending_send = data;
        pending_send_len = len;
        return true;
    }
    void close_conn(Connection& conn) {
        if (conn.on_close) {
            const auto callback = conn.on_close;
            conn.on_close = nullptr;
            callback(this, conn);
        }
        if (conn.req_start_us || conn.epoch_held) {
            conn.req_start_us = 0;
            conn.epoch_held = false;
            epoch_leave();
        }
        conn.h2 = nullptr;
        conn.handler_gen++;
        closed = true;
    }
};
struct GrpcRequestHeaderCapture {
    u32 calls = 0;
    u32 timeout_count = 0;
    u32 timeout_len = 0;
    u32 encoding_count = 0;
    u32 padding_len = 0;
    char timeout[16]{};
    char encoding[16]{};
};
void capture_grpc_request_headers(
    void* ctx, Http2Conn&, u32, const hpack::Header* hs, u32 n, bool) {
    auto* capture = static_cast<GrpcRequestHeaderCapture*>(ctx);
    capture->calls++;
    for (u32 i = 0; i < n; ++i) {
        if (hs[i].name.eq({"grpc-timeout", 12})) {
            capture->timeout_count++;
            capture->timeout_len = hs[i].value.len;
            const u32 len = hs[i].value.len < sizeof(capture->timeout) - 1
                                ? hs[i].value.len
                                : sizeof(capture->timeout) - 1;
            __builtin_memcpy(capture->timeout, hs[i].value.ptr, len);
        } else if (hs[i].name.eq({"grpc-encoding", 13})) {
            capture->encoding_count++;
            const u32 len = hs[i].value.len < sizeof(capture->encoding) - 1
                                ? hs[i].value.len
                                : sizeof(capture->encoding) - 1;
            __builtin_memcpy(capture->encoding, hs[i].value.ptr, len);
        } else if (hs[i].name.eq({"x-padding", 9})) {
            capture->padding_len = hs[i].value.len;
        }
    }
}
void pending_send(void*, Connection&, IoEvent) {}
}  // namespace

TEST(grpc_proxy, grpc_web_h1_deadline_resolves_held_sends_without_mutating_owned_bytes) {
    enum class Case : u8 {
        PartialNative,
        CommittedTrailer,
        CompleteNative,
        ClientFinAfterQueue,
        OrdinaryFin,
    };
    auto run = [&](GrpcWebContentType mode, Case test_case) {
        HeldSendGrpcDriveFixture loop;
        ShardMetrics metrics;
        metrics.init();
        AccessLogRing log;
        log.init();
        loop.metrics = &metrics;
        loop.access_log = &log;

        Connection conn;
        conn.reset();
        u8 send_storage[4096];
        conn.send_buf.bind(send_storage, sizeof(send_storage));
        conn.fd = 41;
        conn.req_start_us = 1;
        conn.req_body_streamed = true;
        conn.request_upload_complete = true;
        conn.req_metadata_episode = 1;
        Http2Conn h2;
        h2.init_client();
        conn.h2 = &h2;
        REQUIRE(h2.open_stream(1) != nullptr);
        h2.grpc.web_h1_kick = &grpc_web_h1_kick_thunk<HeldSendGrpcDriveFixture>;
        conn.on_close = &grpc_connection_closed<HeldSendGrpcDriveFixture>;
        loop.epoch_enter();

        auto* x = reinterpret_cast<GrpcExchange*>(loop.pool.alloc_bulk());
        REQUIRE(x != nullptr);
        x->init();
        x->web_h1 = true;
        x->web_mode = mode;
        x->web_h1_kick = &grpc_web_h1_kick_thunk<HeldSendGrpcDriveFixture>;
        x->downstream = &conn;
        x->downstream_stream = 1;
        x->response_headers_sent = true;
        x->response_status = 0;
        x->deadline_us = 1;
        x->started_us = monotonic_us();
        x->observed = true;
        x->request_end_sent = true;
        if (test_case == Case::PartialNative) {
            const u8 partial[] = {0, 0, 0, 0, 4, 0xaa, 0xbb};
            memcpy(x->download, partial, sizeof(partial));
            x->download_len = sizeof(partial);
        } else if (test_case == Case::CompleteNative || test_case == Case::ClientFinAfterQueue ||
                   test_case == Case::OrdinaryFin) {
            const u8 complete[] = {0, 0, 0, 0, 2, 0xaa, 0xbb};
            memcpy(x->download, complete, sizeof(complete));
            x->download_len = sizeof(complete);
        } else {
            x->response_end = true;
        }
        REQUIRE(grpc_attach(h2, x));

        CHECK(conn.h2 == &h2);
        CHECK(conn.req_body_streamed);
        CHECK_GE(conn.fd, 0);
        CHECK_EQ(grpc_find(h2, 1), x);
        CHECK(x->web_h1);
        CHECK_GT(x->download_len + static_cast<u32>(x->response_end), 0u);
        grpc_web_h1_pump_response(&loop, conn, *x);
        REQUIRE_EQ(loop.sends, 1u);
        REQUIRE_GT(loop.pending_send_len, 0u);
        REQUIRE_EQ(loop.pending_send, conn.send_buf.data());
        u8 owned_bytes[1024];
        REQUIRE_LE(conn.send_buf.len(), sizeof(owned_bytes));
        const u32 owned_len = conn.send_buf.len();
        memcpy(owned_bytes, conn.send_buf.data(), owned_len);
        if (test_case == Case::CommittedTrailer) {
            REQUIRE(x->web_trailer_wire_started);
            if (mode == GrpcWebContentType::Binary) REQUIRE(x->response_end_sent);
        } else {
            REQUIRE(!x->response_end_sent);
        }

        if (test_case == Case::OrdinaryFin) {
            loop.close_conn(conn);
            CHECK_EQ(metrics.grpc_completed[1], 1u);
            CHECK_EQ(metrics.grpc_completed[4], 0u);
            CHECK_EQ(loop.epoch_leaves, 1u);
            AccessLogEntry entry{};
            REQUIRE(log.pop(entry));
            CHECK_EQ(entry.grpc_status_plus_one, 2u);
            CHECK(!log.pop(entry));
            return;
        }

        grpc_deadline_fired(&loop, conn);
        if (test_case == Case::PartialNative || test_case == Case::CommittedTrailer) {
            CHECK(loop.closed);
            CHECK_EQ(loop.sends, 1u);
            CHECK_EQ(metrics.grpc_completed[4], 1u);
            CHECK_EQ(metrics.grpc_completed[1], 0u);
            CHECK_EQ(loop.epoch_leaves, 1u);
            AccessLogEntry entry{};
            REQUIRE(log.pop(entry));
            CHECK_EQ(entry.grpc_status_plus_one, 5u);
            CHECK(!log.pop(entry));
            return;
        }

        CHECK(!loop.closed);
        CHECK(x->web_failure_prepared);
        CHECK(!x->web_response_invalid);
        CHECK_EQ(x->failure, 4u);
        CHECK(x->response_end);
        CHECK_EQ(loop.sends, 1u);
        CHECK_EQ(conn.send_buf.len(), owned_len);
        CHECK_EQ(memcmp(conn.send_buf.data(), owned_bytes, owned_len), 0);
        CHECK_EQ(metrics.grpc_completed[4], 0u);
        CHECK_EQ(loop.epoch_leaves, 0u);

        if (test_case == Case::ClientFinAfterQueue) {
            loop.close_conn(conn);
            CHECK_EQ(metrics.grpc_completed[1], 1u);
            CHECK_EQ(metrics.grpc_completed[4], 0u);
            CHECK_EQ(loop.epoch_leaves, 1u);
            AccessLogEntry entry{};
            REQUIRE(log.pop(entry));
            CHECK_EQ(entry.grpc_status_plus_one, 2u);
            CHECK(!log.pop(entry));
            return;
        }

        grpc_web_h1_on_sent<HeldSendGrpcDriveFixture>(
            &loop, conn, {conn.id, static_cast<i32>(owned_len), 0, 0, IoEventType::Send, 0});
        REQUIRE_EQ(loop.sends, 2u);
        CHECK(x->response_end_sent);
        CHECK(x->web_trailer_wire_started);
        const u32 trailer_send_len = loop.pending_send_len;
        REQUIRE_GT(trailer_send_len, 0u);
        grpc_web_h1_on_sent<HeldSendGrpcDriveFixture>(
            &loop, conn, {conn.id, static_cast<i32>(trailer_send_len), 0, 0, IoEventType::Send, 0});
        CHECK(loop.closed);
        CHECK_EQ(metrics.grpc_completed[4], 1u);
        CHECK_EQ(metrics.grpc_completed[1], 0u);
        CHECK_EQ(loop.epoch_leaves, 1u);
        AccessLogEntry entry{};
        REQUIRE(log.pop(entry));
        CHECK_EQ(entry.grpc_status_plus_one, 5u);
        CHECK(!log.pop(entry));
    };

    run(GrpcWebContentType::Binary, Case::PartialNative);
    run(GrpcWebContentType::Text, Case::PartialNative);
    run(GrpcWebContentType::Binary, Case::CommittedTrailer);
    run(GrpcWebContentType::Text, Case::CommittedTrailer);
    run(GrpcWebContentType::Binary, Case::CompleteNative);
    run(GrpcWebContentType::Binary, Case::ClientFinAfterQueue);
    run(GrpcWebContentType::Binary, Case::OrdinaryFin);
}

TEST(grpc_proxy, grpc_web_h1_text_boundary_flush_does_not_credit_queued_next_message) {
    HeldSendGrpcDriveFixture loop;
    Connection downstream, upstream;
    downstream.reset();
    upstream.reset();
    u8 send_storage[4096];
    downstream.send_buf.bind(send_storage, sizeof(send_storage));
    downstream.fd = 41;
    downstream.req_body_streamed = true;
    downstream.req_metadata_episode = 1;
    Http2Conn downstream_h2, upstream_h2;
    downstream_h2.init_client();
    upstream_h2.init_client();
    upstream_h2.grpc.upstream = true;
    downstream.h2 = &downstream_h2;
    upstream.h2 = &upstream_h2;
    downstream_h2.grpc.web_h1_kick = &grpc_web_h1_kick_thunk<HeldSendGrpcDriveFixture>;
    REQUIRE(downstream_h2.open_stream(1));
    auto* up_stream = upstream_h2.open_stream(1);
    REQUIRE(up_stream);
    up_stream->manual_window = true;
    up_stream->recv_unconsumed = 5;

    GrpcExchange x;
    x.init();
    x.web_h1 = true;
    x.web_mode = GrpcWebContentType::Binary;
    x.web_response_mode = GrpcWebContentType::Text;
    x.downstream = &downstream;
    x.upstream = &upstream;
    x.downstream_stream = x.upstream_stream = 1;
    x.response_headers_sent = true;
    x.web_encode_boundary_pending = true;
    x.response_base64.pending[0] = 0xaa;
    x.response_base64.pending_len = 1;
    const u8 first_message[] = {0, 0, 0, 0, 2, 0xbb};
    REQUIRE_EQ(x.staged_response_message.feed(first_message, sizeof(first_message), false), 0u);
    const u8 next_message[] = {0, 0, 0, 0, 0};
    memcpy(x.download, next_message, sizeof(next_message));
    x.download_len = sizeof(next_message);
    REQUIRE(grpc_attach(downstream_h2, &x));

    grpc_web_h1_pump_response(&loop, downstream, x);
    CHECK_EQ(loop.sends, 1u);
    CHECK_EQ(up_stream->recv_unconsumed, sizeof(next_message));
    CHECK_EQ(up_stream->recv_credit, 0u);
    CHECK_EQ(upstream_h2.conn_recv_credit, 0u);
    CHECK_EQ(x.download_len, sizeof(next_message));
    grpc_detach(downstream_h2, &x);
}

TEST(grpc_proxy, grpc_web_h1_drains_more_than_32_coalesced_chunks) {
    HeldSendGrpcDriveFixture loop;
    Connection downstream, upstream;
    downstream.reset();
    upstream.reset();
    u8 downstream_send[SlicePool::kSliceSize];
    u8 downstream_recv[SlicePool::kSliceSize];
    u8 upstream_send[SlicePool::kSliceSize];
    downstream.send_buf.bind(downstream_send, sizeof(downstream_send));
    downstream.bind_request_receive_buffer(downstream_recv, sizeof(downstream_recv));
    upstream.send_buf.bind(upstream_send, sizeof(upstream_send));
    downstream.fd = 41;
    downstream.req_body_streamed = true;
    downstream.req_body_mode = BodyMode::Chunked;
    downstream.req_metadata_episode = 1;
    downstream.req_chunk_parser.reset();
    downstream.request_upload_complete = false;
    Http2Conn downstream_h2, upstream_h2;
    downstream_h2.init_client();
    upstream_h2.init_client();
    upstream_h2.grpc.upstream = true;
    upstream_h2.grpc.connecting = true;
    downstream.h2 = &downstream_h2;
    upstream.h2 = &upstream_h2;
    downstream_h2.grpc.web_h1_kick = &grpc_web_h1_kick_thunk<HeldSendGrpcDriveFixture>;
    REQUIRE(downstream_h2.open_stream(1));
    REQUIRE(upstream_h2.open_stream(1));
    GrpcExchange x;
    x.init();
    x.web_h1 = true;
    x.web_mode = GrpcWebContentType::Binary;
    x.web_response_mode = GrpcWebContentType::Binary;
    x.downstream = &downstream;
    x.upstream = &upstream;
    x.downstream_stream = x.upstream_stream = 1;
    x.request_message.init(1024);
    REQUIRE(grpc_attach(downstream_h2, &x));
    REQUIRE(grpc_attach(upstream_h2, &x));

    u8 body[405];
    u32 offset = 0;
    for (u32 i = 0; i < 40; i++) {
        memcpy(body + offset, "5\r\n", 3);
        offset += 3;
        const u8 empty_message[] = {0, 0, 0, 0, 0};
        memcpy(body + offset, empty_message, sizeof(empty_message));
        offset += sizeof(empty_message);
        memcpy(body + offset, "\r\n", 2);
        offset += 2;
    }
    memcpy(body + offset, "0\r\n\r\n", 5);
    offset += 5;
    REQUIRE_EQ(offset, sizeof(body));
    memcpy(downstream_recv, body, sizeof(body));
    downstream.recv_buf.commit(sizeof(body));

    grpc_web_h1_resume_upload(&loop, downstream);
    CHECK(downstream.request_upload_complete);
    CHECK_EQ(downstream.recv_buf.len(), 0u);
    CHECK(x.request_end);
    CHECK_EQ(x.failure, 0u);
    CHECK_EQ(x.upload_len, 200u);
    grpc_detach(downstream_h2, &x);
    grpc_detach(upstream_h2, &x);
}

TEST(grpc_proxy, grpc_web_h1_later_receive_validation_failure_kicks_response) {
    HeldSendGrpcDriveFixture loop;
    Connection downstream, upstream;
    downstream.reset();
    upstream.reset();
    u8 downstream_send[SlicePool::kSliceSize];
    u8 downstream_recv[SlicePool::kSliceSize];
    u8 upstream_send[SlicePool::kSliceSize];
    downstream.send_buf.bind(downstream_send, sizeof(downstream_send));
    downstream.bind_request_receive_buffer(downstream_recv, sizeof(downstream_recv));
    upstream.send_buf.bind(upstream_send, sizeof(upstream_send));
    downstream.fd = 41;
    downstream.req_body_streamed = true;
    downstream.req_body_mode = BodyMode::ContentLength;
    downstream.req_body_remaining = 1;
    downstream.req_metadata_episode = 1;
    downstream.request_upload_complete = false;
    Http2Conn downstream_h2, upstream_h2;
    downstream_h2.init_client();
    upstream_h2.init_client();
    upstream_h2.grpc.upstream = true;
    upstream_h2.grpc.connecting = true;
    downstream.h2 = &downstream_h2;
    upstream.h2 = &upstream_h2;
    downstream_h2.grpc.web_h1_kick = &grpc_web_h1_kick_thunk<HeldSendGrpcDriveFixture>;
    REQUIRE(downstream_h2.open_stream(1));
    REQUIRE(upstream_h2.open_stream(1));
    GrpcExchange x;
    x.init();
    x.web_h1 = true;
    x.web_mode = GrpcWebContentType::Binary;
    x.web_response_mode = GrpcWebContentType::Binary;
    x.downstream = &downstream;
    x.upstream = &upstream;
    x.downstream_stream = x.upstream_stream = 1;
    x.request_message.init(1024);
    REQUIRE(grpc_attach(downstream_h2, &x));
    REQUIRE(grpc_attach(upstream_h2, &x));
    downstream_recv[0] = 0x80;  // invalid gRPC compression flag
    downstream.recv_buf.commit(1);

    grpc_web_h1_on_recv<HeldSendGrpcDriveFixture>(
        &loop, downstream, {downstream.id, 1, 0, 0, IoEventType::Recv, 1});
    CHECK_EQ(x.failure, 13u);
    CHECK(x.upstream == nullptr);
    CHECK_GT(loop.sends, 0u);
    CHECK_GT(loop.pending_send_len, 0u);
    CHECK(downstream.on_send != nullptr);
    grpc_detach(downstream_h2, &x);
}

TEST(grpc_proxy, deadline_releases_upstream_while_downstream_send_is_pending) {
    GrpcDriveFixture loop;
    Connection upstream;
    upstream.reset();
    u8 up_storage[SlicePool::kSliceSize];
    upstream.send_slice = up_storage;
    upstream.send_buf.bind(up_storage, sizeof(up_storage));
    Http2Conn up_h2;
    up_h2.init_client();
    up_h2.grpc.upstream = true;
    up_h2.grpc.preface_sent = true;
    up_h2.peer_settings_seen = true;
    upstream.h2 = &up_h2;
    Connection downstream;
    downstream.reset();
    Http2Conn down_h2;
    down_h2.init_client();
    downstream.h2 = &down_h2;
    downstream.on_send = &pending_send;
    auto* down_stream = down_h2.open_stream(1);
    REQUIRE(down_stream != nullptr);
    auto* up_stream = up_h2.open_stream(1);
    REQUIRE(up_stream != nullptr);
    GrpcExchange x;
    x.init();
    x.downstream = &downstream;
    x.upstream = &upstream;
    x.downstream_stream = 1;
    x.upstream_stream = 1;
    x.request_headers_sent = true;
    x.deadline_us = monotonic_us() - 1;
    x.slot_held = true;
    x.upstream_id = 7;
    down_h2.grpc.streams[0] = &x;
    down_h2.grpc.active = 1;
    up_h2.grpc.streams[0] = &x;
    up_h2.grpc.active = 1;
    grpc_deadline_fired(&loop, downstream);
    CHECK_EQ(x.failure, 4u);
    CHECK(x.upstream == nullptr);
    CHECK_FALSE(x.slot_held);
    CHECK_EQ(loop.released, 1u);
    CHECK_EQ(down_h2.grpc.active, 1u);
    CHECK_EQ(up_h2.grpc.active, 0u);
    CHECK_EQ(up_stream->state, Http2StreamState::Closed);
    CHECK_GT(loop.sends, 0u);
    CHECK(downstream.on_send == &pending_send);
}

TEST(grpc_proxy, rst_failure_drains_other_exchange_when_deadline_arm_fails) {
    GrpcDriveFixture loop;
    REQUIRE(loop.pool_ready);
    Connection upstream;
    upstream.reset();
    u8 upstream_send[SlicePool::kSliceSize];
    u8 upstream_recv[SlicePool::kSliceSize];
    upstream.send_slice = upstream_send;
    upstream.send_buf.bind(upstream_send, sizeof(upstream_send));
    upstream.recv_slice = upstream_recv;
    upstream.recv_slice_capacity = sizeof(upstream_recv);
    upstream.recv_buf.bind(upstream_recv, sizeof(upstream_recv));
    Http2Conn upstream_h2;
    upstream_h2.init_client();
    upstream_h2.grpc.upstream = true;
    upstream_h2.grpc.preface_sent = true;
    upstream_h2.peer_settings_seen = true;
    upstream_h2.preface_seen = true;
    upstream_h2.our_settings_sent = true;
    upstream.h2 = &upstream_h2;

    Connection downstream;
    downstream.reset();
    u8 downstream_send[SlicePool::kSliceSize];
    u8 downstream_recv[SlicePool::kSliceSize];
    downstream.send_slice = downstream_send;
    downstream.send_buf.bind(downstream_send, sizeof(downstream_send));
    downstream.bind_request_receive_buffer(downstream_recv, sizeof(downstream_recv));
    Http2Conn downstream_h2;
    downstream_h2.init_client();
    downstream.h2 = &downstream_h2;
    REQUIRE(downstream_h2.open_stream(1) != nullptr);
    REQUIRE(downstream_h2.open_stream(3) != nullptr);
    REQUIRE(upstream_h2.open_stream(1) != nullptr);
    REQUIRE(upstream_h2.open_stream(3) != nullptr);
    auto* reset_exchange = reinterpret_cast<GrpcExchange*>(loop.pool.alloc_bulk());
    auto* pending_exchange = reinterpret_cast<GrpcExchange*>(loop.pool.alloc_bulk());
    REQUIRE(reset_exchange != nullptr);
    REQUIRE(pending_exchange != nullptr);
    reset_exchange->init();
    pending_exchange->init();
    reset_exchange->downstream = pending_exchange->downstream = &downstream;
    reset_exchange->upstream = pending_exchange->upstream = &upstream;
    reset_exchange->downstream_stream = reset_exchange->upstream_stream = 1;
    pending_exchange->downstream_stream = pending_exchange->upstream_stream = 3;
    pending_exchange->deadline_us = monotonic_us() + 1000000;
    pending_exchange->request_headers_sent = true;
    pending_exchange->slot_held = true;
    pending_exchange->upstream_id = 7;
    downstream_h2.grpc.streams[0] = reset_exchange;
    downstream_h2.grpc.streams[1] = pending_exchange;
    downstream_h2.grpc.active = 2;
    upstream_h2.grpc.streams[0] = reset_exchange;
    upstream_h2.grpc.streams[1] = pending_exchange;
    upstream_h2.grpc.active = 2;

    // Feed an actual upstream RST_STREAM through the production callback. The
    // callback's first downstream kick is suppressed while the H2 parser is
    // busy; the post-parser refresh must drain both exchanges when arming the
    // deadline timer fails, without another caller pump.
    upstream.bind_request_receive_buffer(upstream_recv, sizeof(upstream_recv));
    const u32 rst_len = write_rst_stream(upstream_recv, 1, Http2Error::Cancel);
    upstream.recv_buf.commit(rst_len);
    grpc_on_upstream_data<GrpcDriveFixture>(
        &loop, upstream, {upstream.id, 1, 0, 0, IoEventType::Recv, 1});

    CHECK_EQ(upstream_h2.grpc.active, 0u);
    CHECK_EQ(loop.released, 1u);
    CHECK_EQ(downstream_h2.grpc.active, 1u);
    CHECK_EQ(pending_exchange->failure, 8u);
    CHECK(pending_exchange->upstream == nullptr);
    CHECK_FALSE(pending_exchange->slot_held);
    CHECK_EQ(downstream_h2.grpc.timer_deadline_us, 0u);
    CHECK_GT(loop.sends, loop.downstream_sends);
    CHECK(loop.downstream_sends > 0);
    CHECK_GT(loop.downstream_last_send_len, 0u);
}

TEST(grpc_proxy, client_reset_restores_keepalive_after_grpc_release) {
    GrpcDriveFixture loop;
    REQUIRE(loop.pool_ready);
    auto run = [&](bool precise) {
        Connection downstream;
        downstream.reset();
        u8 send[SlicePool::kSliceSize];
        u8 recv[SlicePool::kSliceSize];
        downstream.send_slice = send;
        downstream.send_buf.bind(send, sizeof(send));
        downstream.bind_request_receive_buffer(recv, sizeof(recv));
        Http2Conn h2;
        h2.init_client();
        h2.preface_seen = true;
        h2.our_settings_sent = true;
        h2.peer_settings_seen = true;
        downstream.h2 = &h2;
        auto* stream = h2.open_stream(1);
        REQUIRE(stream != nullptr);
        stream->state = Http2StreamState::Open;
        auto* x = reinterpret_cast<GrpcExchange*>(loop.pool.alloc_bulk());
        REQUIRE(x != nullptr);
        x->init();
        x->downstream = &downstream;
        x->downstream_stream = 1;
        h2.grpc.streams[0] = x;
        h2.grpc.active = 1;
        if (precise) {
            h2.grpc.timer_deadline_us = monotonic_us() + 1000000;
            downstream.yield_armed = true;
        } else {
            loop.timer.refresh(&downstream, 1);
        }
        const u32 rst_len = write_rst_stream(recv, 1, Http2Error::Cancel);
        downstream.recv_buf.commit(rst_len);
        on_h2_data<GrpcDriveFixture>(
            &loop, downstream, {downstream.id, 1, 0, 0, IoEventType::Recv, 1});
        CHECK_EQ(h2.grpc.active, 0u);
        CHECK_EQ(h2.grpc.timer_deadline_us, 0u);
        CHECK_FALSE(downstream.yield_armed);
        CHECK(downstream.timer_node.next != &downstream.timer_node);
        u32 timer_slot = TimerWheel::kSlots;
        for (u32 i = 0; i < TimerWheel::kSlots; i++)
            for (auto* node = loop.timer.slots[i].next; node != &loop.timer.slots[i];
                 node = node->next)
                if (node == &downstream.timer_node) timer_slot = i;
        CHECK_EQ(timer_slot,
                 (loop.timer.cursor + loop.keepalive_timeout) & (TimerWheel::kSlots - 1));
        loop.timer.remove(&downstream);
    };
    run(false);
    run(true);
}

TEST(grpc_proxy, backend_reset_releases_slot_while_downstream_send_is_pending) {
    GrpcDriveFixture loop;
    REQUIRE(loop.pool_ready);
    Connection upstream;
    upstream.reset();
    u8 upstream_send[SlicePool::kSliceSize];
    u8 upstream_recv[SlicePool::kSliceSize];
    upstream.send_slice = upstream_send;
    upstream.send_buf.bind(upstream_send, sizeof(upstream_send));
    upstream.bind_request_receive_buffer(upstream_recv, sizeof(upstream_recv));
    Http2Conn upstream_h2;
    upstream_h2.init_client();
    upstream_h2.grpc.upstream = true;
    upstream_h2.grpc.preface_sent = true;
    upstream_h2.peer_settings_seen = true;
    upstream_h2.preface_seen = true;
    upstream_h2.our_settings_sent = true;
    upstream.h2 = &upstream_h2;

    Connection downstream;
    downstream.reset();
    u8 downstream_send[SlicePool::kSliceSize];
    u8 downstream_recv[SlicePool::kSliceSize];
    downstream.send_slice = downstream_send;
    downstream.send_buf.bind(downstream_send, sizeof(downstream_send));
    downstream.bind_request_receive_buffer(downstream_recv, sizeof(downstream_recv));
    downstream.on_send = &pending_send;
    Http2Conn downstream_h2;
    downstream_h2.init_client();
    downstream.h2 = &downstream_h2;
    REQUIRE(downstream_h2.open_stream(1) != nullptr);
    REQUIRE(upstream_h2.open_stream(1) != nullptr);

    auto* x = reinterpret_cast<GrpcExchange*>(loop.pool.alloc_bulk());
    REQUIRE(x != nullptr);
    x->init();
    x->downstream = &downstream;
    x->upstream = &upstream;
    x->downstream_stream = x->upstream_stream = 1;
    x->request_headers_sent = true;
    x->download_len = 17;
    x->slot_held = true;
    x->upstream_id = 7;
    downstream_h2.grpc.streams[0] = x;
    downstream_h2.grpc.active = 1;
    upstream_h2.grpc.streams[0] = x;
    upstream_h2.grpc.active = 1;
    auto* upstream_stream = upstream_h2.find_stream(1);
    REQUIRE(upstream_stream != nullptr);
    upstream_stream->manual_window = true;
    upstream_stream->recv_unconsumed = x->download_len;

    const u32 rst_len = write_rst_stream(upstream_recv, 1, Http2Error::Cancel);
    upstream.recv_buf.commit(rst_len);
    grpc_on_upstream_data<GrpcDriveFixture>(
        &loop, upstream, {upstream.id, 1, 0, 0, IoEventType::Recv, 1});

    CHECK_EQ(upstream_h2.grpc.active, 0u);
    CHECK_EQ(loop.released, 1u);
    CHECK_EQ(downstream_h2.grpc.active, 1u);
    CHECK_EQ(x->failure, 1u);
    CHECK(x->response_end);
    CHECK(x->upstream == nullptr);
    CHECK_FALSE(x->slot_held);
    CHECK_EQ(upstream_h2.grpc.control_len, 0u);
    CHECK(loop.saw_window_update);
    CHECK_EQ(downstream_h2.grpc.timer_deadline_us, 0u);
    grpc_detach(downstream_h2, x);
    loop.pool.free(reinterpret_cast<u8*>(x));
}

TEST(grpc_proxy, direct_http2_proxy_rejects_missing_scheme_before_upstream) {
    GrpcDriveFixture loop;
    REQUIRE(loop.pool_ready);
    RouteConfig cfg;
    REQUIRE(cfg.add_upstream("grpc", 0x7f000001, 50051).has_value());
    cfg.upstreams[0].http2 = true;
    REQUIRE(cfg.add_proxy("/svc", static_cast<u8>('P'), 0));
    Connection downstream;
    downstream.reset();
    Http2Conn h2;
    h2.init_client();
    downstream.h2 = &h2;
    REQUIRE(h2.open_stream(1) != nullptr);
    downstream.request_config = &cfg;
    u8 response[4096];
    H2Dispatch<GrpcDriveFixture> d{&loop, &downstream, response, sizeof(response), 0, false};
    const hpack::Header headers[] = {{{":method", 7}, {"POST", 4}},
                                     {{":path", 5}, {"/svc", 4}},
                                     {{":authority", 10}, {"backend", 7}},
                                     {{"content-type", 12}, {"application/grpc", 16}}};
    h2_dispatch_request(d, 1, headers, 4, true);
    CHECK_GT(d.resp_len, 0u);
    CHECK_EQ(h2.grpc.active, 0u);
    CHECK(loop.grpc_upstreams == nullptr);
    CHECK_EQ(downstream.send_buf.len(), 0u);
}

TEST(grpc_proxy, grpc_pump_is_not_blocked_by_ordinary_outbound_window) {
    GrpcDriveFixture loop;
    REQUIRE(loop.pool_ready);
    Connection downstream;
    downstream.reset();
    u8 send[SlicePool::kSliceSize];
    u8 recv[SlicePool::kSliceSize];
    downstream.send_slice = send;
    downstream.send_buf.bind(send, sizeof(send));
    downstream.bind_request_receive_buffer(recv, sizeof(recv));
    Http2Conn h2;
    h2.init_client();
    h2.preface_seen = true;
    h2.our_settings_sent = true;
    h2.peer_settings_seen = true;
    downstream.h2 = &h2;
    auto* ordinary = h2.open_stream(1);
    auto* grpc_stream = h2.open_stream(3);
    REQUIRE(ordinary != nullptr);
    REQUIRE(grpc_stream != nullptr);
    ordinary->state = Http2StreamState::Open;
    ordinary->send_window = 0;
    h2.outbound_stream = 1;
    static const u8 body[] = {'x'};
    h2.outbound_body = body;
    h2.outbound_body_len = sizeof(body);
    h2.outbound_body_offset = 0;
    h2.conn_send_window = 65535;
    auto* x = reinterpret_cast<GrpcExchange*>(loop.pool.alloc_bulk());
    REQUIRE(x != nullptr);
    x->init();
    x->downstream = &downstream;
    x->downstream_stream = 3;
    x->failure = 1;
    x->response_end = true;
    h2.grpc.streams[0] = x;
    h2.grpc.active = 1;
    on_h2_data<GrpcDriveFixture>(&loop, downstream, {downstream.id, 1, 0, 0, IoEventType::Recv, 1});
    CHECK(loop.saw_downstream_stream3);
    CHECK_EQ(h2.outbound_stream, 1u);
    CHECK_EQ(ordinary->send_window, 0);
}

TEST(grpc_proxy, pooled_session_respects_peer_stream_limit_while_exchange_retires) {
    GrpcDriveFixture loop;
    Connection upstream;
    upstream.reset();
    u8 send_storage[SlicePool::kSliceSize];
    upstream.send_slice = send_storage;
    upstream.send_buf.bind(send_storage, sizeof(send_storage));
    Http2Conn h2;
    h2.init();
    h2.client = true;
    h2.grpc.upstream = true;
    h2.grpc.preface_sent = true;
    h2.preface_seen = true;
    h2.our_settings_sent = true;
    h2.peer_settings_seen = true;
    upstream.h2 = &h2;

    Connection downstream;
    downstream.reset();
    GrpcExchange retained;
    GrpcExchange queued;
    GrpcExchange newest;
    retained.init();
    queued.init();
    newest.init();
    retained.downstream = queued.downstream = newest.downstream = &downstream;
    retained.upstream = queued.upstream = newest.upstream = &upstream;
    retained.upstream_stream = 1;
    queued.upstream_stream = 3;
    newest.upstream_stream = 5;
    retained.request_headers_sent = true;
    const hpack::Header request_headers[] = {{{":method", 7}, {"POST", 4}},
                                             {{":path", 5}, {"/svc", 4}},
                                             {{"content-type", 12}, {"application/grpc", 16}}};
    queued.request_headers_len = http2_write_headers(
        queued.request_headers, GrpcExchange::kHeaders, 3, request_headers, 3, false);
    newest.request_headers_len = http2_write_headers(
        newest.request_headers, GrpcExchange::kHeaders, 5, request_headers, 3, false);
    REQUIRE(queued.request_headers_len > kFrameHeaderSize);
    REQUIRE(newest.request_headers_len > kFrameHeaderSize);
    REQUIRE(h2.open_stream(1) != nullptr);
    REQUIRE(h2.open_stream(3) != nullptr);
    REQUIRE(h2.open_stream(5) != nullptr);
    h2.peer_settings.has_max_concurrent_streams = true;
    h2.peer_settings.max_concurrent_streams = 1;
    h2.grpc.streams[0] = &retained;
    h2.grpc.streams[1] = &queued;
    h2.grpc.streams[2] = &newest;
    h2.grpc.active = 3;
    loop.grpc_upstreams = &upstream;
    RouteConfig cfg;
    REQUIRE(cfg.add_upstream("grpc", 0x7f000001, 1).has_value());
    cfg.upstreams[0].http2 = true;
    upstream.request_config = &cfg;
    upstream.upstream_idx = 0;
    upstream.upstream_backend_idx = 0;

    CHECK(grpc_upstream_reusable(upstream, &cfg, 0, 0));
    CHECK_FALSE(grpc_upstream_reusable(upstream, nullptr, 0, 0));
    CHECK_FALSE(grpc_upstream_reusable(upstream, &cfg, 0, 1));
    h2.grpc.active = 64;
    CHECK_FALSE(grpc_upstream_reusable(upstream, &cfg, 0, 0));
    h2.grpc.active = 3;
    h2.peer_goaway = true;
    CHECK_FALSE(grpc_upstream_reusable(upstream, &cfg, 0, 0));
    h2.peer_goaway = false;
    h2.last_stream_id = 0x7ffffffd;
    CHECK_FALSE(grpc_upstream_reusable(upstream, &cfg, 0, 0));
    h2.last_stream_id = 5;

    auto* retained_stream = h2.find_stream(1);
    REQUIRE(retained_stream != nullptr);
    retained.failure = 14;
    retained.response_end = true;
    retained_stream->state = Http2StreamState::HalfClosedRemote;
    downstream.on_send = &pending_send;
    // The response on stream 1 has ended, but its exchange remains attached
    // while the blocked downstream drains it. The half-closed upstream stream
    // still counts against the peer limit until the stream is closed locally.
    CHECK_EQ(h2.grpc.control_len, 0u);
    CHECK_EQ(h2.conn_recv_credit, 0u);
    CHECK(h2.peer_settings_seen);
    grpc_drive_upstream(&loop, upstream);
    CHECK_EQ(loop.sends, 0u);
    CHECK_FALSE(queued.request_headers_sent);
    CHECK_FALSE(newest.request_headers_sent);
    CHECK_EQ(loop.grpc_upstreams, &upstream);

    retained_stream->state = Http2StreamState::Closed;
    grpc_drive_upstream(&loop, upstream);
    CHECK_GT(loop.sends, 0u);
    CHECK(queued.request_headers_sent);
    CHECK_FALSE(newest.request_headers_sent);
    CHECK_EQ(h2.grpc.active, 3u);
    CHECK_EQ(h2.peer_settings.max_concurrent_streams, 1u);
}

TEST(grpc_proxy, timer_resume_forward_uses_http2_exchange_and_replays_buffered_data) {
    EpollEventLoop loop;
    REQUIRE(loop.init(0, -1).has_value());
    RouteConfig cfg;
    REQUIRE(cfg.add_upstream("grpc", 0x7f000001, 1).has_value());
    cfg.upstreams[0].http2 = true;
    Connection* down = loop.alloc_conn();
    REQUIRE(down != nullptr);
    REQUIRE(loop.alloc_h2(*down));
    down->h2->init();
    down->h2->client = true;
    down->protocol = ConnProtocol::Http2;
    down->request_config = &cfg;
    REQUIRE(down->h2->open_stream(1) != nullptr);
    const char* synth =
        "POST /svc HTTP/1.1\r\nhost: x\r\ncontent-type: application/grpc\r\ncontent-length: "
        "3\r\n\r\n";
    const u32 synth_len = static_cast<u32>(__builtin_strlen(synth));
    for (u32 i = 0; i < synth_len; i++) down->h2->pending_synth[i] = static_cast<u8>(synth[i]);
    ParsedRequest open;
    open.reset();
    open.has_content_length = true;
    open.content_length = 3;
    open.content_length_count = 1;
    u8 response[8192]{};
    H2Dispatch<EpollEventLoop> d{&loop, down, response, sizeof(response), 0, false};
    JitDispatchOutcome yielded{};
    yielded.kind = JitDispatchOutcome::Kind::TimerYield;
    yielded.next_state = 1;
    yielded.timer_ms = 100;
    REQUIRE(h2_suspend_timer(d,
                             1,
                             &grpc_jit_forward,
                             yielded,
                             &cfg,
                             down->h2->pending_synth,
                             synth_len,
                             true,
                             true,
                             false,
                             &open));
    down->pending_handler_fn = &grpc_jit_forward;
    down->handler_state = 1;
    const u32 frame_len = http2_write_data(
        down->recv_buf.write_ptr(), 1, reinterpret_cast<const u8*>("abc"), 3, true);
    down->recv_buf.commit(frame_len);
    h2_resume_jit_handler(&loop, *down);
    CHECK_EQ(down->h2->async_stream, 0u);
    CHECK_EQ(down->h2->grpc.active, 1u);
    CHECK(loop.grpc_upstreams != nullptr);
    GrpcExchange* exchange = nullptr;
    for (u32 i = 0; i < 64; i++)
        if (down->h2->grpc.streams[i]) exchange = down->h2->grpc.streams[i];
    REQUIRE(exchange != nullptr);
    CHECK(exchange->upstream != nullptr);
    CHECK(exchange->upstream->h2 != nullptr);
    CHECK(exchange->upstream->h2->grpc.upstream);
    loop.force_close_all();
    loop.shutdown();
}

struct FailConnectLoop : EpollEventLoop {
    u32 recv_submits = 0;
    u32 connect_submits = 0;
    Connection* last_connect_conn = nullptr;
    bool submit_connect(Connection& conn, const void*, u32) {
        connect_submits++;
        last_connect_conn = &conn;
        return false;
    }
    bool detach_upstream_close(Connection& conn) {
        if (conn.upstream_fd >= 0) close(conn.upstream_fd);
        conn.upstream_fd = -1;
        conn.upstream_connect_armed = false;
        conn.upstream_recv_armed = false;
        conn.upstream_send_armed = false;
        return true;
    }
    bool submit_recv(Connection& conn) {
        recv_submits++;
        return EpollEventLoop::submit_recv(conn);
    }
};

TEST(grpc_proxy, resumed_forward_immediate_connect_failure_emits_without_client_input) {
    GrpcBackendHealthReset health_reset{};
    auto* health = backend_health(0, 0);
    REQUIRE(health != nullptr);
    FailConnectLoop loop;
    REQUIRE(loop.init(0, -1).has_value());
    RouteConfig cfg;
    REQUIRE(cfg.add_upstream("grpc", 0x7f000001, 1).has_value());
    REQUIRE(cfg.upstreams[0].add_addr(0x7f000001, 2));
    REQUIRE(cfg.upstreams[0].add_addr(0x7f000001, 3));
    cfg.upstreams[0].http2 = true;
    Connection* down = loop.alloc_conn();
    REQUIRE(down != nullptr);
    REQUIRE(loop.alloc_h2(*down));
    down->h2->init();
    down->h2->client = true;
    down->protocol = ConnProtocol::Http2;
    down->request_config = &cfg;
    const RouteConfig* cfg_ptr = &cfg;
    loop.config_ptr = &cfg_ptr;
    REQUIRE(down->h2->open_stream(1) != nullptr);
    const char* synth = "POST /svc HTTP/1.1\r\nhost: x\r\ncontent-type: application/grpc\r\n\r\n";
    const u32 synth_len = static_cast<u32>(__builtin_strlen(synth));
    for (u32 i = 0; i < synth_len; i++) down->h2->pending_synth[i] = static_cast<u8>(synth[i]);
    ParsedRequest open;
    open.reset();
    u8 response[8192]{};
    H2Dispatch<FailConnectLoop> d{&loop, down, response, sizeof(response), 0, false};
    JitDispatchOutcome yielded{};
    yielded.kind = JitDispatchOutcome::Kind::TimerYield;
    yielded.next_state = 1;
    yielded.timer_ms = 100;
    REQUIRE(h2_suspend_timer(d,
                             1,
                             &grpc_jit_forward,
                             yielded,
                             &cfg,
                             down->h2->pending_synth,
                             synth_len,
                             true,
                             true,
                             false,
                             &open));
    down->pending_handler_fn = &grpc_jit_forward;
    down->handler_state = 1;
    h2_resume_jit_handler(&loop, *down);
    CHECK_EQ(down->h2->async_stream, 0u);
    CHECK_EQ(down->h2->grpc.active, 0u);
    CHECK_GT(down->send_buf.len(), 0u);
    CHECK(down->h2->grpc.streams[0] == nullptr);
    CHECK(loop.grpc_upstreams == nullptr);
    CHECK_EQ(loop.recv_submits, 0u);
    CHECK_EQ(loop.connect_submits, 3u);
    CHECK_EQ(loop.grpc_upstreams, nullptr);
    for (u32 i = 0; i < cfg.upstreams[0].addr_count; i++) {
        auto* backend = backend_health(0, i);
        REQUIRE(backend != nullptr);
        CHECK_EQ(backend->fails, 0u);
    }
    REQUIRE(loop.last_connect_conn != nullptr);
    CHECK(loop.last_connect_conn->timer_node.next == &loop.last_connect_conn->timer_node);
    CHECK(loop.last_connect_conn->timer_node.prev == &loop.last_connect_conn->timer_node);
    loop.force_close_all();
    loop.shutdown();
}

TEST(grpc_proxy, resumed_jit_forward_snapshots_response_mutations) {
    EpollEventLoop loop;
    REQUIRE(loop.init(0, -1).has_value());
    RouteConfig cfg;
    REQUIRE(cfg.add_upstream("grpc", 0x7f000001, 1).has_value());
    cfg.upstreams[0].http2 = true;
    Connection* down = loop.alloc_conn();
    REQUIRE(down != nullptr);
    REQUIRE(loop.alloc_h2(*down));
    down->h2->init();
    down->h2->client = true;
    down->protocol = ConnProtocol::Http2;
    down->request_config = &cfg;
    REQUIRE(down->h2->open_stream(1) != nullptr);
    const char* synth = "POST /svc HTTP/1.1\r\nhost: x\r\ncontent-type: application/grpc\r\n\r\n";
    const u32 synth_len = static_cast<u32>(__builtin_strlen(synth));
    for (u32 i = 0; i < synth_len; i++) down->h2->pending_synth[i] = static_cast<u8>(synth[i]);
    ParsedRequest open;
    open.reset();
    u8 response[8192]{};
    H2Dispatch<EpollEventLoop> d{&loop, down, response, sizeof(response), 0, false};
    auto* initial_ctx = down->reset_jit_ctx();
    grpc_jit_mutating_forward(down, initial_ctx, nullptr, 0, nullptr);
    JitDispatchOutcome yielded{};
    yielded.kind = JitDispatchOutcome::Kind::TimerYield;
    yielded.next_state = 1;
    yielded.timer_ms = 1;
    REQUIRE(h2_suspend_timer(d,
                             1,
                             &grpc_jit_mutating_forward,
                             yielded,
                             &cfg,
                             down->h2->pending_synth,
                             synth_len,
                             true,
                             true,
                             false,
                             &open));
    down->pending_handler_fn = &grpc_jit_mutating_forward;
    down->handler_state = 1;
    h2_resume_jit_handler(&loop, *down);
    CHECK_EQ(down->h2->async_stream, 0u);
    CHECK_EQ(down->h2->grpc.active, 1u);
    auto* x = down->h2->grpc.streams[0];
    REQUIRE(x != nullptr);
    CHECK_EQ(x->response_mutation_count, 2u);
    CHECK(x->response_mutations[0].mode ==
          static_cast<u8>(Connection::RespHeaderMutationMode::Set));
    CHECK(x->response_mutations[1].mode ==
          static_cast<u8>(Connection::RespHeaderMutationMode::Remove));
    const char* first_name = reinterpret_cast<const char*>(x->response_mutation_storage +
                                                           x->response_mutations[0].name_offset);
    const char* first_value = reinterpret_cast<const char*>(x->response_mutation_storage +
                                                            x->response_mutations[0].value_offset);
    const Str first_name_str{first_name, x->response_mutations[0].name_len};
    const Str first_value_str{first_value, x->response_mutations[0].value_len};
    CHECK(first_name_str.eq({"x-jit", 5}));
    CHECK(first_value_str.eq({"first", 5}));
    loop.force_close_all();
    loop.shutdown();
}

TEST(grpc_proxy, upstream_session_close_releases_slots_with_blocked_downstream) {
    GrpcDriveFixture loop;
    REQUIRE(loop.pool_ready);
    Connection upstream;
    upstream.reset();
    Http2Conn upstream_h2;
    upstream_h2.init_client();
    upstream_h2.grpc.upstream = true;
    upstream.h2 = &upstream_h2;
    loop.grpc_upstreams = &upstream;
    Connection downstream;
    downstream.reset();
    u8 downstream_send[SlicePool::kSliceSize];
    u8 downstream_recv[SlicePool::kSliceSize];
    downstream.send_slice = downstream_send;
    downstream.send_buf.bind(downstream_send, sizeof(downstream_send));
    downstream.bind_request_receive_buffer(downstream_recv, sizeof(downstream_recv));
    downstream.on_send = &pending_send;
    Http2Conn downstream_h2;
    downstream_h2.init_client();
    downstream.h2 = &downstream_h2;
    REQUIRE(downstream_h2.open_stream(1) != nullptr);
    REQUIRE(downstream_h2.open_stream(3) != nullptr);
    REQUIRE(upstream_h2.open_stream(1) != nullptr);
    REQUIRE(upstream_h2.open_stream(3) != nullptr);
    GrpcExchange* exchanges[2];
    for (u32 i = 0; i < 2; i++) {
        exchanges[i] = reinterpret_cast<GrpcExchange*>(loop.pool.alloc_bulk());
        REQUIRE(exchanges[i] != nullptr);
        exchanges[i]->init();
        exchanges[i]->downstream = &downstream;
        exchanges[i]->upstream = &upstream;
        exchanges[i]->downstream_stream = exchanges[i]->upstream_stream = 1 + i * 2;
        exchanges[i]->slot_held = true;
        exchanges[i]->upstream_id = 7 + i;
        downstream_h2.grpc.streams[i] = exchanges[i];
        upstream_h2.grpc.streams[i] = exchanges[i];
    }
    downstream_h2.grpc.active = upstream_h2.grpc.active = 2;
    grpc_connection_closed<GrpcDriveFixture>(&loop, upstream);
    CHECK_EQ(upstream_h2.grpc.active, 0u);
    CHECK_EQ(loop.grpc_upstreams, nullptr);
    CHECK_EQ(loop.released, 2u);
    for (auto* x : exchanges) {
        CHECK(x->upstream == nullptr);
        CHECK_FALSE(x->slot_held);
        CHECK_EQ(x->failure, 14u);
        CHECK(x->response_end);
    }
    CHECK_EQ(downstream_h2.grpc.active, 2u);
    grpc_connection_closed<GrpcDriveFixture>(&loop, upstream);
    CHECK_EQ(loop.released, 2u);
    for (auto* x : exchanges) {
        grpc_detach(downstream_h2, x);
        loop.pool.free(reinterpret_cast<u8*>(x));
    }
}

TEST(grpc_proxy, terminal_response_releases_slot_while_downstream_send_is_blocked) {
    GrpcDriveFixture loop;
    Connection upstream;
    upstream.reset();
    Connection downstream;
    downstream.reset();
    u8 downstream_send[SlicePool::kSliceSize];
    downstream.send_slice = downstream_send;
    downstream.send_buf.bind(downstream_send, sizeof(downstream_send));
    downstream.on_send = &pending_send;
    Http2Conn upstream_h2;
    upstream_h2.init_client();
    upstream_h2.grpc.upstream = true;
    upstream.h2 = &upstream_h2;
    Http2Conn downstream_h2;
    downstream_h2.init_client();
    downstream.h2 = &downstream_h2;
    REQUIRE(upstream_h2.open_stream(1) != nullptr);
    REQUIRE(upstream_h2.open_stream(3) != nullptr);
    REQUIRE(downstream_h2.open_stream(1) != nullptr);
    REQUIRE(downstream_h2.open_stream(3) != nullptr);
    GrpcExchange trailers;
    trailers.init();
    trailers.downstream = &downstream;
    trailers.upstream = &upstream;
    trailers.downstream_stream = trailers.upstream_stream = 1;
    trailers.slot_held = true;
    trailers.upstream_id = 7;
    upstream_h2.grpc.streams[0] = &trailers;
    downstream_h2.grpc.streams[0] = &trailers;
    GrpcExchange headers;
    headers.init();
    headers.downstream = &downstream;
    headers.upstream = &upstream;
    headers.downstream_stream = headers.upstream_stream = 3;
    headers.slot_held = true;
    headers.upstream_id = 7;
    upstream_h2.grpc.streams[1] = &headers;
    downstream_h2.grpc.streams[1] = &headers;
    upstream_h2.grpc.active = downstream_h2.grpc.active = 2;
    GrpcClientDispatch<GrpcDriveFixture> dispatch{&loop, &upstream};
    const hpack::Header trailer_headers[] = {
        {Str{"grpc-status", 11}, Str{"0", 1}},
    };
    grpc_response_trailers<GrpcDriveFixture>(&dispatch, upstream_h2, 1, trailer_headers, 1, true);
    CHECK_FALSE(trailers.slot_held);
    CHECK_EQ(loop.released, 1u);
    CHECK(trailers.response_end);
    CHECK_GT(trailers.response_trailers_len, 0u);
    CHECK_EQ(upstream_h2.grpc.streams[0], &trailers);
    CHECK_EQ(downstream_h2.grpc.streams[0], &trailers);
    CHECK_EQ(upstream_h2.grpc.active, 2u);
    CHECK_EQ(downstream_h2.grpc.active, 2u);
    grpc_response_trailers<GrpcDriveFixture>(&dispatch, upstream_h2, 1, trailer_headers, 1, true);
    CHECK_EQ(loop.released, 1u);

    const hpack::Header terminal_headers[] = {
        {Str{":status", 7}, Str{"200", 3}},
        {Str{"content-type", 12}, Str{"application/grpc", 16}},
        {Str{"grpc-status", 11}, Str{"0", 1}},
        {Str{"X-Old", 5}, Str{"gone", 4}},
        {Str{"x-trace", 7}, Str{"upstream", 8}},
    };
    downstream.resp_header_mutations[0] = {
        {"X-Trace", 7}, {"jit", 3}, Connection::RespHeaderMutationMode::Set};
    downstream.resp_header_mutations[1] = {
        {"X-Old", 5}, {nullptr, 0}, Connection::RespHeaderMutationMode::Remove};
    downstream.resp_header_mutations[2] = {
        {"grpc-status", 11}, {nullptr, 0}, Connection::RespHeaderMutationMode::Remove};
    downstream.resp_header_mutation_count = 3;
    REQUIRE(grpc_snapshot_response_mutations(downstream, headers));
    grpc_response_headers<GrpcDriveFixture>(&dispatch, upstream_h2, 3, terminal_headers, 5, true);
    CHECK_FALSE(headers.slot_held);
    CHECK_EQ(loop.released, 2u);
    CHECK_EQ(headers.failure, 2u);
    CHECK(headers.response_end);
    CHECK_GT(headers.response_headers_len, 0u);
    CHECK((headers.response_headers[4] & 0x1u) != 0);
    Http2FrameHeader response_frame;
    REQUIRE(parse_frame_header(headers.response_headers,
                               headers.response_headers_len,
                               &response_frame) == ParseStatus::Complete);
    hpack::DynamicTable response_dyn;
    response_dyn.init(4096);
    hpack::Header decoded_headers[16];
    u8 response_scratch[512];
    u32 decoded_count = 0;
    REQUIRE(hpack::decode_header_block(response_dyn,
                                       headers.response_headers + kFrameHeaderSize,
                                       response_frame.length,
                                       response_scratch,
                                       sizeof(response_scratch),
                                       decoded_headers,
                                       16,
                                       &decoded_count));
    bool saw_trace = false;
    bool saw_old = false;
    for (u32 i = 0; i < decoded_count; i++) {
        if (decoded_headers[i].name.eq({"x-trace", 7}) && decoded_headers[i].value.eq({"jit", 3}))
            saw_trace = true;
        if (decoded_headers[i].name.eq({"x-old", 5})) saw_old = true;
    }
    CHECK(saw_trace);
    CHECK_FALSE(saw_old);
    CHECK_EQ(upstream_h2.grpc.streams[1], &headers);
    CHECK_EQ(downstream_h2.grpc.streams[1], &headers);
    CHECK_EQ(upstream_h2.grpc.active, 2u);
    CHECK_EQ(downstream_h2.grpc.active, 2u);
    CHECK(downstream.on_send == &pending_send);
}

TEST(grpc_proxy, nonzero_grpc_status_clears_backend_health) {
    GrpcBackendHealthReset health_reset{};
    auto* health = backend_health(0, 0);
    REQUIRE(health != nullptr);
    health->fails = 2;
    GrpcDriveFixture loop;
    Connection upstream;
    upstream.reset();
    upstream.upstream_idx = 0;
    upstream.upstream_backend_idx = 0;
    Connection downstream;
    downstream.reset();
    Http2Conn upstream_h2;
    upstream_h2.init_client();
    upstream_h2.grpc.upstream = true;
    upstream.h2 = &upstream_h2;
    Http2Conn downstream_h2;
    downstream_h2.init_client();
    downstream.h2 = &downstream_h2;
    REQUIRE(upstream_h2.open_stream(1) != nullptr);
    REQUIRE(downstream_h2.open_stream(1) != nullptr);
    GrpcExchange x;
    x.init();
    x.upstream = &upstream;
    x.downstream = &downstream;
    x.upstream_stream = x.downstream_stream = 1;
    x.slot_held = true;
    x.upstream_id = 0;
    REQUIRE(grpc_attach(upstream_h2, &x));
    REQUIRE(grpc_attach(downstream_h2, &x));
    upstream_h2.grpc.active = downstream_h2.grpc.active = 1;
    GrpcClientDispatch<GrpcDriveFixture> dispatch{&loop, &upstream};
    const hpack::Header response[] = {
        {{":status", 7}, {"200", 3}},
        {{"content-type", 12}, {"application/grpc", 16}},
        {{"grpc-status", 11}, {"7", 1}},
    };
    grpc_response_headers<GrpcDriveFixture>(&dispatch, upstream_h2, 1, response, 3, true);
    CHECK_EQ(health->fails, 0u);
    CHECK_FALSE(x.failure);
    CHECK(x.response_end);
    CHECK_FALSE(x.slot_held);
}

TEST(grpc_proxy, trailers_only_status_observes_response_mutations) {
    GrpcDriveFixture loop;
    Connection upstream;
    upstream.reset();
    Connection downstream;
    downstream.reset();
    Http2Conn upstream_h2;
    upstream_h2.init_client();
    upstream_h2.grpc.upstream = true;
    upstream.h2 = &upstream_h2;
    Http2Conn downstream_h2;
    downstream_h2.init_client();
    downstream.h2 = &downstream_h2;
    REQUIRE(upstream_h2.open_stream(1) != nullptr);
    REQUIRE(downstream_h2.open_stream(1) != nullptr);
    GrpcExchange x;
    x.init();
    x.upstream = &upstream;
    x.downstream = &downstream;
    x.upstream_stream = x.downstream_stream = 1;
    REQUIRE(grpc_attach(upstream_h2, &x));
    REQUIRE(grpc_attach(downstream_h2, &x));
    upstream_h2.grpc.active = downstream_h2.grpc.active = 1;
    downstream.resp_header_mutations[0] = {
        {"grpc-status", 11}, {"7", 1}, Connection::RespHeaderMutationMode::Set};
    downstream.resp_header_mutation_count = 1;
    REQUIRE(grpc_snapshot_response_mutations(downstream, x));
    GrpcClientDispatch<GrpcDriveFixture> dispatch{&loop, &upstream};
    const hpack::Header response[] = {
        {{":status", 7}, {"200", 3}},
        {{"content-type", 12}, {"application/grpc", 16}},
        {{"grpc-status", 11}, {"0", 1}},
    };
    grpc_response_headers<GrpcDriveFixture>(&dispatch, upstream_h2, 1, response, 3, true);
    CHECK_EQ(x.response_status, 7u);
    CHECK_EQ(x.failure, 0u);

    // Snapshot a second Add mutation through the public mutation path so a
    // duplicate grpc-status is classified as UNKNOWN after filtering.
    downstream.resp_header_mutations[0] = {
        {"grpc-status", 11}, {"0", 1}, Connection::RespHeaderMutationMode::Add};
    REQUIRE(grpc_snapshot_response_mutations(downstream, x));
    hpack::Header filtered[8];
    u32 filtered_n = 1;
    filtered[0] = response[2];
    REQUIRE(grpc_apply_response_mutations(x, filtered, &filtered_n, 8));
    CHECK_EQ(grpc_observed_status(filtered, filtered_n), 2u);
}

TEST(grpc_proxy, refused_stream_retry_survives_protocol_close_in_same_process) {
    RetryCloseGrpcDriveFixture loop;
    Connection upstream;
    upstream.reset();
    u8 up_recv[64]{};
    upstream.bind_request_receive_buffer(up_recv, sizeof(up_recv));
    Http2Conn up_h2;
    up_h2.init_client();
    up_h2.grpc.upstream = true;
    up_h2.grpc.preface_sent = true;
    up_h2.peer_settings_seen = true;
    upstream.h2 = &up_h2;
    Connection downstream;
    downstream.reset();
    Http2Conn down_h2;
    down_h2.init_client();
    downstream.h2 = &down_h2;
    REQUIRE(up_h2.open_stream(1) != nullptr);
    auto* down_stream = down_h2.open_stream(1);
    REQUIRE(down_stream != nullptr);
    down_stream->manual_window = true;
    down_stream->recv_unconsumed = 3;
    GrpcExchange x;
    x.init();
    x.upstream = &upstream;
    x.downstream = &downstream;
    x.upstream_stream = x.downstream_stream = 1;
    x.slot_held = true;
    x.request_headers_sent = true;
    x.upload_len = 3;
    x.retry_enabled = true;
    x.retry_policy = {2, 16, 1u << 14, 0};
    x.retry_attempts = 1;
    x.retry_tried_mask = 1;
    REQUIRE(x.replay_body.init(16));
    REQUIRE(x.replay_body.seal());
    const hpack::Header request[] = {{{":method", 7}, {"POST", 4}}};
    REQUIRE(x.replay_headers.capture(request, 1));
    REQUIRE(x.replay_trailers.capture(nullptr, 0));
    up_h2.grpc.streams[0] = &x;
    up_h2.grpc.active = 1;
    down_h2.grpc.streams[0] = &x;
    down_h2.grpc.active = 1;
    upstream.on_close = &grpc_connection_closed<RetryCloseGrpcDriveFixture>;
    loop.grpc_upstreams = &upstream;

    u32 len = write_rst_stream(up_recv, 1, Http2Error::RefusedStream);
    // A one-byte SETTINGS payload is a connection protocol error. The parser
    // must finish dispatching REFUSED_STREAM before close retires the session.
    u8* bad_settings = up_recv + len;
    bad_settings[0] = 0;
    bad_settings[1] = 0;
    bad_settings[2] = 1;
    bad_settings[3] = static_cast<u8>(Http2FrameType::Settings);
    bad_settings[4] = 0;
    __builtin_memset(bad_settings + 5, 0, 4);
    bad_settings[9] = 0;
    len += 10;
    upstream.recv_buf.commit(len);
    grpc_on_upstream_data<RetryCloseGrpcDriveFixture>(
        &loop, upstream, {upstream.id, 1, 0, 0, IoEventType::Recv, 1});

    CHECK(loop.closed);
    CHECK_EQ(up_h2.grpc.active, 0u);
    CHECK_EQ(down_h2.grpc.active, 1u);
    CHECK_EQ(down_h2.grpc.streams[0], &x);
    CHECK(x.retry_pending);
    CHECK(x.upstream == nullptr);
    CHECK(x.slot_held);
    CHECK_EQ(x.failure, 0u);
    CHECK_EQ(loop.released, 0u);
    CHECK_EQ(down_h2.conn_recv_credit, 3u);
    CHECK_EQ(x.upload_len, 0u);
    grpc_detach_retry_attempt(&loop, x);
    CHECK_EQ(down_h2.conn_recv_credit, 3u);
}

TEST(grpc_proxy, c5_exhaustion_retries_only_complete_logical_exchanges) {
    RetryCloseGrpcDriveFixture loop;
    Connection upstream;
    upstream.reset();
    Http2Conn up_h2;
    up_h2.init_client();
    up_h2.grpc.upstream = true;
    up_h2.grpc.connecting = true;
    up_h2.grpc.c5_exhausted = true;
    upstream.h2 = &up_h2;
    loop.grpc_upstreams = &upstream;
    Connection down_complete, down_incomplete;
    down_complete.reset();
    down_incomplete.reset();
    down_complete.on_send = down_incomplete.on_send = &pending_send;
    Http2Conn complete_h2, incomplete_h2;
    complete_h2.init_client();
    incomplete_h2.init_client();
    down_complete.h2 = &complete_h2;
    down_incomplete.h2 = &incomplete_h2;
    REQUIRE(complete_h2.open_stream(1) != nullptr);
    REQUIRE(incomplete_h2.open_stream(1) != nullptr);
    REQUIRE(up_h2.open_stream(1) != nullptr);
    REQUIRE(up_h2.open_stream(3) != nullptr);
    GrpcExchange complete, incomplete;
    complete.init();
    incomplete.init();
    complete.downstream = &down_complete;
    incomplete.downstream = &down_incomplete;
    complete.upstream = incomplete.upstream = &upstream;
    complete.downstream_stream = complete.upstream_stream = 1;
    incomplete.downstream_stream = 1;
    incomplete.upstream_stream = 3;
    complete.slot_held = incomplete.slot_held = true;
    complete.retry_enabled = incomplete.retry_enabled = true;
    complete.retry_policy = incomplete.retry_policy = {2, 16, 1u << 7, 10};
    complete.retry_attempts = incomplete.retry_attempts = 1;
    REQUIRE(complete.replay_body.init(16));
    REQUIRE(complete.replay_body.seal());
    REQUIRE(incomplete.replay_body.init(16));  // Streaming body is not sealed.
    const hpack::Header request[] = {{{":method", 7}, {"POST", 4}}};
    REQUIRE(complete.replay_headers.capture(request, 1));
    REQUIRE(complete.replay_trailers.capture(nullptr, 0));
    REQUIRE(incomplete.replay_headers.capture(request, 1));
    REQUIRE(incomplete.replay_trailers.capture(nullptr, 0));
    up_h2.grpc.streams[0] = &complete;
    up_h2.grpc.streams[1] = &incomplete;
    up_h2.grpc.active = 2;
    complete_h2.grpc.streams[0] = &complete;
    complete_h2.grpc.active = 1;
    incomplete_h2.grpc.streams[0] = &incomplete;
    incomplete_h2.grpc.active = 1;

    grpc_connection_closed<RetryCloseGrpcDriveFixture>(&loop, upstream);
    CHECK(complete.retry_pending);
    CHECK(complete.upstream == nullptr);
    CHECK(complete.slot_held);
    CHECK_EQ(complete_h2.grpc.active, 1u);
    CHECK_EQ(incomplete.failure, 14u);
    CHECK(incomplete.response_end);
    CHECK(incomplete.upstream == nullptr);
    CHECK_FALSE(incomplete.slot_held);
    CHECK_EQ(loop.released, 1u);
    CHECK_EQ(up_h2.grpc.active, 0u);
    complete.replay_body.release();
    incomplete.replay_body.release();
}

TEST(grpc_proxy, c5_exhaustion_carries_tried_backends_into_logical_retry) {
    GrpcBackendHealthReset health_reset{};
    RetryCloseSelectionFixture loop;
    REQUIRE(loop.pool_ready);
    RouteConfig cfg;
    REQUIRE(cfg.add_upstream("grpc", 0x7f000001, 1));
    for (u32 i = 1; i < 4; i++) REQUIRE(cfg.upstreams[0].add_addr(0x7f000001, 1));
    cfg.upstreams[0].http2 = true;
    cfg.upstreams[0].grpc_retry = {3, 16, 1u << 14, 0};

    Connection upstream;
    upstream.reset();
    Http2Conn upstream_h2;
    upstream_h2.init_client();
    upstream_h2.grpc.upstream = true;
    upstream_h2.grpc.connecting = true;
    upstream_h2.grpc.c5_exhausted = true;
    upstream_h2.grpc.connect_attempts = 3;
    upstream_h2.grpc.connect_tried_mask = 0x07;
    upstream.h2 = &upstream_h2;
    loop.grpc_upstreams = &upstream;

    Connection downstream;
    downstream.reset();
    Http2Conn downstream_h2;
    downstream_h2.init_client();
    downstream.h2 = &downstream_h2;
    REQUIRE(downstream_h2.open_stream(1) != nullptr);
    REQUIRE(upstream_h2.open_stream(1) != nullptr);

    GrpcExchange exchange;
    exchange.init();
    exchange.downstream = &downstream;
    exchange.upstream = &upstream;
    exchange.downstream_stream = exchange.upstream_stream = 1;
    exchange.config_epoch = &cfg;
    exchange.upstream_id = 0;
    exchange.retry_policy = cfg.upstreams[0].grpc_retry;
    exchange.retry_enabled = true;
    exchange.retry_attempts = 1;
    exchange.retry_tried_mask = 1u;
    exchange.slot_held = true;
    REQUIRE(exchange.replay_body.init(16));
    REQUIRE(exchange.replay_body.seal());
    const hpack::Header request[] = {{{":method", 7}, {"POST", 4}}};
    REQUIRE(exchange.replay_headers.capture(request, 1));
    REQUIRE(exchange.replay_trailers.capture(nullptr, 0));
    upstream_h2.grpc.streams[0] = &exchange;
    upstream_h2.grpc.active = 1;
    downstream_h2.grpc.streams[0] = &exchange;
    downstream_h2.grpc.active = 1;

    grpc_connection_closed<RetryCloseSelectionFixture>(&loop, upstream);

    CHECK(exchange.retry_pending);
    CHECK_EQ(exchange.retry_tried_mask, 0x07u);
    CHECK(exchange.upstream == nullptr);
    CHECK(exchange.slot_held);
    CHECK_EQ(downstream_h2.grpc.active, 1u);
    CHECK_EQ(upstream_h2.grpc.active, 0u);
    REQUIRE(grpc_bind_retry_attempt(&loop, exchange, monotonic_us()));
    CHECK_EQ(loop.retry_conn.upstream_backend_idx, 3u);
    CHECK_EQ(exchange.retry_tried_mask, 0x0fu);
    CHECK_EQ(exchange.retry_attempts, 2u);

    const u32 fallback_start = select_backend(0, 4, monotonic_us());
    CHECK_EQ(grpc_select_retry_backend(0, 4, 0x0f, monotonic_us()), (fallback_start + 1) % 4);
    grpc_detach(loop.retry_h2, &exchange);
    grpc_detach(downstream_h2, &exchange);
    exchange.upstream = nullptr;
    exchange.replay_body.release();
    loop.grpc_upstreams = nullptr;
    loop.retry_conn.on_close = nullptr;
    if (loop.retry_conn.fd >= 0) close(loop.retry_conn.fd);
    loop.retry_conn.fd = loop.retry_conn.upstream_fd = -1;
    if (loop.retry_conn.recv_slice) loop.pool.free(loop.retry_conn.recv_slice);
}

TEST(grpc_proxy, parser_failure_records_active_session_once) {
    GrpcBackendHealthReset health_reset{};
    auto* health = backend_health(0, 0);
    REQUIRE(health != nullptr);
    GrpcDriveFixture loop;
    Connection conn;
    conn.reset();
    u8 recv[32]{};
    conn.bind_request_receive_buffer(recv, sizeof(recv));
    conn.recv_buf.commit(sizeof(recv));
    Http2Conn h2;
    h2.init_client();
    h2.grpc.upstream = true;
    h2.grpc.active = 1;
    conn.h2 = &h2;
    conn.upstream_idx = 0;
    conn.upstream_backend_idx = 0;
    grpc_on_upstream_data<GrpcDriveFixture>(&loop, conn, {conn.id, 1, 0, 0, IoEventType::Recv, 1});
    CHECK(loop.closed);
    CHECK_EQ(health->fails, 1u);
    grpc_record_session_failure(&loop, conn, monotonic_us());
    CHECK_EQ(health->fails, 1u);
}

TEST(grpc_proxy, rejected_tls_identity_ejects_backend_once) {
    GrpcBackendHealthReset health_reset{};
    auto* health = backend_health(0, 0);
    REQUIRE(health != nullptr);
    GrpcDriveFixture loop;
    RouteConfig cfg;
    REQUIRE(cfg.add_upstream("grpc", 0x7f000001, 1));
    cfg.upstreams[0].http2 = true;
    cfg.upstreams[0].tls.enabled = true;
    cfg.upstreams[0].grpc_retry = {3, 1024, 1u << 14, 0};
    const RouteConfig* active = &cfg;
    loop.config_ptr = &active;
    Connection conn;
    conn.reset();
    conn.request_config = &cfg;
    conn.upstream_idx = 0;
    conn.upstream_backend_idx = 0;
    Http2Conn h2;
    h2.init_client();
    h2.grpc.upstream = true;
    h2.grpc.client_tls.ssl_ctx = SSL_CTX_new(TLS_client_method());
    REQUIRE(h2.grpc.client_tls.ssl_ctx != nullptr);
    conn.h2 = &h2;
    conn.tls = SSL_new(h2.grpc.client_tls.ssl_ctx);
    REQUIRE(conn.tls != nullptr);
    GrpcExchange identity_exchange;
    identity_exchange.init();
    identity_exchange.upstream = &conn;
    identity_exchange.retry_enabled = true;
    identity_exchange.retry_policy = cfg.upstreams[0].grpc_retry;
    identity_exchange.replay_body.replayable = true;
    identity_exchange.replay_body.sealed = true;
    identity_exchange.replay_headers.valid = true;
    identity_exchange.replay_trailers.valid = true;
    h2.grpc.streams[0] = &identity_exchange;
    h2.grpc.active = 1;
    u8 send_bytes[] = {0};
    conn.send_buf.bind(send_bytes, sizeof(send_bytes));
    conn.send_buf.commit(1);
    grpc_on_upstream_sent<GrpcDriveFixture>(&loop, conn, {conn.id, 1, 0, 0, IoEventType::Send, 0});
    CHECK(loop.closed);
    grpc_connection_closed<GrpcDriveFixture>(&loop, conn);
    CHECK_FALSE(identity_exchange.retry_pending);
    CHECK(identity_exchange.response_end);
    CHECK_EQ(identity_exchange.failure, 14u);
    CHECK_EQ(identity_exchange.retry_attempts, 0u);
    CHECK_EQ(health->fails, 1u);
    grpc_record_handshake_result(&loop, conn, false, monotonic_us());
    CHECK_EQ(health->fails, 1u);
    SSL_free(conn.tls);
    conn.tls = nullptr;
    SSL_CTX_free(h2.grpc.client_tls.ssl_ctx);
    h2.grpc.client_tls.ssl_ctx = nullptr;

    health->fails = 0;
    RouteConfig bad_tls_cfg;
    REQUIRE(bad_tls_cfg.add_upstream("grpc", 0x7f000001, 1).has_value());
    bad_tls_cfg.upstreams[0].http2 = true;
    bad_tls_cfg.upstreams[0].tls.enabled = true;
    active = &bad_tls_cfg;
    Connection setup_failure;
    setup_failure.reset();
    setup_failure.request_config = &bad_tls_cfg;
    setup_failure.upstream_idx = 0;
    setup_failure.upstream_backend_idx = 0;
    Http2Conn setup_h2;
    setup_h2.init_client();
    setup_h2.grpc.upstream = true;
    setup_failure.h2 = &setup_h2;
    grpc_connected<GrpcDriveFixture>(
        &loop, setup_failure, {setup_failure.id, 0, 0, 0, IoEventType::UpstreamConnect, 0});
    CHECK(loop.closed);
    CHECK_EQ(health->fails, 1u);
}

TEST(grpc_proxy, timer_resume_expired_grpc_timeout_is_cancelled_before_forward) {
    EpollEventLoop loop;
    REQUIRE(loop.init(0, -1).has_value());
    RouteConfig cfg;
    REQUIRE(cfg.add_upstream("grpc", 0x7f000001, 1).has_value());
    cfg.upstreams[0].http2 = true;
    Connection* down = loop.alloc_conn();
    REQUIRE(down != nullptr);
    REQUIRE(loop.alloc_h2(*down));
    down->h2->init();
    down->h2->client = true;
    down->protocol = ConnProtocol::Http2;
    down->request_config = &cfg;
    auto* stream = down->h2->open_stream(1);
    REQUIRE(stream != nullptr);
    stream->headers_received_us = monotonic_us() - 1000;
    const char* synth =
        "POST /svc HTTP/1.1\r\nhost: x\r\ncontent-type: application/grpc\r\n"
        "grpc-timeout: 1u\r\ncontent-length: 3\r\n\r\n";
    const u32 synth_len = static_cast<u32>(__builtin_strlen(synth));
    for (u32 i = 0; i < synth_len; i++) down->h2->pending_synth[i] = static_cast<u8>(synth[i]);
    ParsedRequest open;
    open.reset();
    open.has_content_length = true;
    open.content_length = 3;
    open.content_length_count = 1;
    u8 response[8192]{};
    H2Dispatch<EpollEventLoop> d{&loop, down, response, sizeof(response), 0, false};
    JitDispatchOutcome yielded{};
    yielded.kind = JitDispatchOutcome::Kind::TimerYield;
    yielded.next_state = 1;
    yielded.timer_ms = 100;
    REQUIRE(h2_suspend_timer(d,
                             1,
                             &grpc_jit_forward,
                             yielded,
                             &cfg,
                             down->h2->pending_synth,
                             synth_len,
                             true,
                             true,
                             false,
                             &open));
    down->pending_handler_fn = &grpc_jit_forward;
    down->handler_state = 1;
    h2_resume_jit_handler(&loop, *down);
    CHECK_EQ(down->h2->async_stream, 0u);
    CHECK_EQ(down->h2->grpc.active, 0u);
    CHECK_GT(down->send_buf.len(), 0u);
    CHECK_EQ(loop.grpc_upstreams, nullptr);
    loop.force_close_all();
    loop.shutdown();
}

TEST(grpc_proxy, h2_receive_promotion_replaces_full_ordinary_slice) {
    EpollEventLoop loop;
    REQUIRE(loop.init(0, -1).has_value());
    Connection* conn = loop.alloc_conn();
    REQUIRE(conn != nullptr);
    const u32 ordinary = conn->recv_buf.capacity();
    REQUIRE(ordinary < kDefaultMaxFrameSize + kFrameHeaderSize);
    for (u32 i = 0; i < ordinary; i++) conn->recv_buf.write_ptr()[i] = static_cast<u8>(i);
    conn->recv_buf.commit(ordinary);
    u8* old = conn->recv_slice;
    REQUIRE(grpc_grow_recv(&loop, *conn));
    CHECK(conn->recv_slice != old);
    CHECK(loop.pool.is_bulk(conn->recv_slice));
    CHECK_EQ(conn->recv_buf.len(), ordinary);
    loop.force_close_all();
    loop.shutdown();
}

template <typename Loop>
void grpc_web_h2_case(rut::test::TestCase* _tc) {
    (void)_tc;
    auto server = std::make_unique<EchoServer>();
    REQUIRE(server->start());
    auto shard = std::make_unique<Shard<Loop>>();
    const int lfd = create_listen_socket(0).value_or(-1);
    REQUIRE(lfd >= 0);
    if (!shard->init(0, lfd).has_value()) {
        close(lfd);
        SKIP("backend unavailable");
    }
    REQUIRE(shard->init_access_log().has_value());
    RouteConfig cfg;
    REQUIRE(cfg.add_upstream("grpc", 0x7f000001, get_port(server->listen_fd)).has_value());
    cfg.upstreams[0].http2 = true;
    REQUIRE(cfg.add_proxy("/test.Echo/", 'P', 0));
    shard->route_config = &cfg;
    REQUIRE(shard->spawn(-1).has_value());
    u32 expected_trailer_size = 0;
    {
        Client client;
        const bool connected = client.init(get_port(lfd));
        CHECK(connected);
        if (connected) {
            const u8 grpc_body[] = {0, 0, 0, 0, 3, 0xff, 0xfe, 0xfd};
            u8 text_body[64];
            GrpcWebBase64Encoder encoder{};
            encoder.init();
            u32 consumed = 0, written = 0, flush_written = 0;
            CHECK_EQ(
                encoder.feed(
                    grpc_body, sizeof(grpc_body), consumed, text_body, sizeof(text_body), written),
                GrpcWebCodecStatus::Ok);
            CHECK_EQ(consumed, sizeof(grpc_body));
            CHECK_EQ(encoder.flush(text_body + written, sizeof(text_body) - written, flush_written),
                     GrpcWebCodecStatus::Ok);
            const u32 text_len = written + flush_written;
            GrpcWebTrailer trailers[] = {{{"grpc-status", 11}, {"0", 1}},
                                         {{"x-trailer", 9}, {"present", 7}}};
            u8 expected_trailer[128];
            u32 expected_trailer_len = 0;
            REQUIRE(grpc_web_encode_trailer_envelope(
                trailers, 2, expected_trailer, sizeof(expected_trailer), expected_trailer_len));
            expected_trailer_size = expected_trailer_len;
            for (u32 i = 0; i < 6; i++) {
                const bool text = i >= 3;
                const u32 window_size = (i % 3) + 1;
                nghttp2_settings_entry window{NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, window_size};
                CHECK_EQ(nghttp2_submit_settings(client.session, 0, &window, 1), 0);
                const u8* request_body = text ? text_body : grpc_body;
                const u32 request_len = text ? text_len : sizeof(grpc_body);
                CHECK_EQ(
                    client.request_web(i, request_body, request_len, text, i % 2 ? 1 : 2, true),
                    static_cast<int>(i * 2 + 1));
                CHECK(client.until(i, true));
                const auto& rpc = client.rpcs[i];
                CHECK(rpc.web_content_type);
                CHECK(rpc.meta);
                u8 decoded[256];
                u32 decoded_len = 0;
                if (text) {
                    GrpcWebBase64Decoder decoder{};
                    decoder.init();
                    u32 input_consumed = 0, output_written = 0;
                    CHECK_EQ(decoder.feed(rpc.response.get(),
                                          rpc.response_len,
                                          input_consumed,
                                          decoded,
                                          sizeof(decoded),
                                          output_written),
                             GrpcWebCodecStatus::Ok);
                    CHECK_EQ(input_consumed, rpc.response_len);
                    CHECK_EQ(decoder.finish(), GrpcWebCodecStatus::Ok);
                    decoded_len = output_written;
                } else {
                    CHECK_LE(rpc.response_len, sizeof(decoded));
                    decoded_len = rpc.response_len;
                    memcpy(decoded, rpc.response.get(), decoded_len);
                }
                CHECK_EQ(decoded_len, sizeof(grpc_body) + expected_trailer_len);
                if (decoded_len == sizeof(grpc_body) + expected_trailer_len) {
                    CHECK(memcmp(decoded, grpc_body, sizeof(grpc_body)) == 0);
                    CHECK(memcmp(decoded + sizeof(grpc_body),
                                 expected_trailer,
                                 expected_trailer_len) == 0);
                }
            }
            auto decode_text = [](const Client::Rpc& rpc, u8* output, u32 capacity) {
                GrpcWebBase64Decoder decoder{};
                decoder.init();
                u32 consumed = 0, written = 0;
                if (decoder.feed(rpc.response.get(),
                                 rpc.response_len,
                                 consumed,
                                 output,
                                 capacity,
                                 written) != GrpcWebCodecStatus::Ok ||
                    consumed != rpc.response_len || decoder.finish() != GrpcWebCodecStatus::Ok)
                    return 0u;
                return written;
            };
            auto contains = [](const u8* bytes, u32 size, const char* value, u32 value_len) {
                if (value_len > size) return false;
                for (u32 i = 0; i <= size - value_len; i++)
                    if (memcmp(bytes + i, value, value_len) == 0) return true;
                return false;
            };
            u8 multi_frames[14] = {0, 0, 0, 0, 2, 0xaa, 0xbb, 0, 0, 0, 0, 2, 0xcc, 0xdd};
            u8 multi_text[32];
            u32 multi_text_len = 0;
            for (u32 offset = 0; offset < sizeof(multi_frames); offset += 7) {
                GrpcWebBase64Encoder block{};
                block.init();
                u32 block_consumed = 0, block_written = 0, block_flush = 0;
                CHECK_EQ(block.feed(multi_frames + offset,
                                    7,
                                    block_consumed,
                                    multi_text + multi_text_len,
                                    sizeof(multi_text) - multi_text_len,
                                    block_written),
                         GrpcWebCodecStatus::Ok);
                CHECK_EQ(block_consumed, 7u);
                CHECK_EQ(block.flush(multi_text + multi_text_len + block_written,
                                     sizeof(multi_text) - multi_text_len - block_written,
                                     block_flush),
                         GrpcWebCodecStatus::Ok);
                multi_text_len += block_written + block_flush;
            }
            CHECK_EQ(multi_text_len, 24u);
            CHECK_EQ(client.request_web(6, multi_text, multi_text_len, true, 1, true), 13);
            CHECK(client.until(6, true));
            u8 multi_decoded[256];
            const u32 multi_decoded_len =
                decode_text(client.rpcs[6], multi_decoded, sizeof(multi_decoded));
            CHECK_EQ(multi_decoded_len, sizeof(multi_frames) + expected_trailer_len);
            if (multi_decoded_len == sizeof(multi_frames) + expected_trailer_len) {
                CHECK(memcmp(multi_decoded, multi_frames, sizeof(multi_frames)) == 0);
                CHECK(memcmp(multi_decoded + sizeof(multi_frames),
                             expected_trailer,
                             expected_trailer_len) == 0);
            }
            server->reply_mode = 1;
            CHECK_EQ(client.request_web(7, grpc_body, sizeof(grpc_body), false, 2), 15);
            CHECK(client.until(7, true));
            u8 error_envelope[256];
            u32 error_len = client.rpcs[7].response_len;
            CHECK(error_len <= sizeof(error_envelope));
            if (error_len <= sizeof(error_envelope))
                memcpy(error_envelope, client.rpcs[7].response.get(), error_len);
            CHECK(error_len >= 5);
            if (error_len >= 5) {
                CHECK_EQ(error_envelope[0], 0x80u);
                const u32 payload_len = (static_cast<u32>(error_envelope[1]) << 24) |
                                        (static_cast<u32>(error_envelope[2]) << 16) |
                                        (static_cast<u32>(error_envelope[3]) << 8) |
                                        error_envelope[4];
                CHECK_EQ(payload_len, error_len - 5);
                CHECK(contains(error_envelope + 5, payload_len, "grpc-status: 7", 14));
            }
            server->reply_mode = 2;
            CHECK_EQ(client.request_web(8, grpc_body, sizeof(grpc_body), false, 2), 17);
            CHECK(client.until(8, true));
            CHECK(client.rpcs[8].response_len >= 5);
            if (client.rpcs[8].response_len >= 5) {
                CHECK_EQ(client.rpcs[8].response[0], 0x80u);
                CHECK(contains(client.rpcs[8].response.get() + 5,
                               client.rpcs[8].response_len - 5,
                               "grpc-status: 14",
                               15));
            }
            CHECK_EQ(server->grpc_content_type_requests.load(), 9u);
            CHECK_EQ(server->te_trailers_requests.load(), 9u);
            CHECK_EQ(server->bad_web_request_headers.load(), 0u);
            CHECK_EQ(server->text_marker_requests.load(), 4u);
            CHECK_EQ(server->text_content_length_requests.load(), 0u);
            const u8 invalid_base64[] = {'A', 'B', '=', 'C'};
            CHECK_EQ(client.request_web(9, invalid_base64, sizeof(invalid_base64), true, 1, true),
                     19);
            CHECK(client.until(9, true));
            u8 invalid_response[256];
            const u32 invalid_response_len =
                decode_text(client.rpcs[9], invalid_response, sizeof(invalid_response));
            CHECK(invalid_response_len >= 5);
            if (invalid_response_len >= 5) {
                CHECK_EQ(invalid_response[0], 0x80u);
                CHECK(contains(
                    invalid_response + 5, invalid_response_len - 5, "grpc-status: 13", 15));
            }
            nghttp2_settings_entry full_window{NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 65535};
            CHECK_EQ(nghttp2_submit_settings(client.session, 0, &full_window, 1), 0);
            u8 large_request[70005] = {0, 0, 1, 0x11, 0x70};
            for (u32 i = 5; i < sizeof(large_request); i++)
                large_request[i] = static_cast<u8>((i * 31u + i / 251u) & 255u);
            CHECK_EQ(
                client.request_web(10, large_request, sizeof(large_request), false, 16384, true),
                21);
            CHECK(client.until(10, true));
            CHECK_EQ(client.rpcs[10].response_len, sizeof(large_request) + expected_trailer_len);
            if (client.rpcs[10].response_len == sizeof(large_request) + expected_trailer_len) {
                CHECK(memcmp(client.rpcs[10].response.get(),
                             large_request,
                             sizeof(large_request)) == 0);
                CHECK(memcmp(client.rpcs[10].response.get() + sizeof(large_request),
                             expected_trailer,
                             expected_trailer_len) == 0);
            }
            constexpr u32 kPayloadLen = 130000;
            constexpr u32 kNativeLen = kPayloadLen + 5;
            auto native = std::make_unique<u8[]>(kNativeLen);
            native[0] = 0;
            native[1] = static_cast<u8>(kPayloadLen >> 24);
            native[2] = static_cast<u8>(kPayloadLen >> 16);
            native[3] = static_cast<u8>(kPayloadLen >> 8);
            native[4] = static_cast<u8>(kPayloadLen);
            for (u32 i = 5; i < kNativeLen; i++)
                native[i] = static_cast<u8>((i * 73u + i / 127u + 19u) & 255u);
            u64 native_hash = 14695981039346656037ull;
            for (u32 i = 0; i < kNativeLen; i++) {
                native_hash ^= native[i];
                native_hash *= 1099511628211ull;
            }
            auto native_to_text = [&](u8* output, u32 capacity) {
                GrpcWebBase64Encoder large_encoder{};
                large_encoder.init();
                u32 native_consumed = 0, encoded = 0, padding = 0;
                CHECK_EQ(large_encoder.feed(
                             native.get(), kNativeLen, native_consumed, output, capacity, encoded),
                         GrpcWebCodecStatus::Ok);
                CHECK_EQ(native_consumed, kNativeLen);
                CHECK_EQ(large_encoder.flush(output + encoded, capacity - encoded, padding),
                         GrpcWebCodecStatus::Ok);
                return encoded + padding;
            };
            auto base64_wire_size = [](u32 len) { return ((len + 2) / 3) * 4; };
            const u32 content_types_before = server->grpc_content_type_requests.load();
            const u32 te_trailers_before = server->te_trailers_requests.load();
            const u32 text_markers_before = server->text_marker_requests.load();
            u32 text_cases_completed = 0;
            for (u32 case_index = 0; case_index < 4; case_index++) {
                const bool text = (case_index & 1) != 0;
                const u32 rpc_index = 11 + case_index;
                std::unique_ptr<u8[]> text_body;
                u32 request_len = kNativeLen;
                const u8* request_body = native.get();
                if (text) {
                    text_body = std::make_unique<u8[]>(base64_wire_size(kNativeLen));
                    request_len = native_to_text(text_body.get(), base64_wire_size(kNativeLen));
                    request_body = text_body.get();
                }
                const u32 client_updates_before = client.window_updates;
                const u32 server_updates_before = server->window_updates.load();
                CHECK_EQ(
                    client.request_web(rpc_index, request_body, request_len, text, 16384, text),
                    static_cast<int>(rpc_index * 2 + 1));
                CHECK(client.until(rpc_index, true));
                const auto& large_rpc = client.rpcs[rpc_index];
                CHECK(large_rpc.web_content_type);
                CHECK(large_rpc.meta);
                CHECK_EQ(large_rpc.sent, request_len);
                CHECK(large_rpc.response_end);
                const u32 decoded_size = kNativeLen + expected_trailer_len;
                if (text) {
                    CHECK_EQ(large_rpc.response_len,
                             base64_wire_size(kNativeLen) + base64_wire_size(expected_trailer_len));
                    auto decoded = std::make_unique<u8[]>(decoded_size);
                    GrpcWebBase64Decoder large_decoder{};
                    large_decoder.init();
                    u32 raw_consumed = 0, raw_written = 0;
                    CHECK_EQ(large_decoder.feed(large_rpc.response.get(),
                                                large_rpc.response_len,
                                                raw_consumed,
                                                decoded.get(),
                                                decoded_size,
                                                raw_written),
                             GrpcWebCodecStatus::Ok);
                    CHECK_EQ(raw_consumed, large_rpc.response_len);
                    CHECK_EQ(large_decoder.finish(), GrpcWebCodecStatus::Ok);
                    CHECK_EQ(raw_written, decoded_size);
                    if (raw_written == decoded_size) {
                        CHECK_EQ(memcmp(decoded.get(), native.get(), kNativeLen), 0);
                        CHECK_EQ(
                            memcmp(
                                decoded.get() + kNativeLen, expected_trailer, expected_trailer_len),
                            0);
                    }
                } else {
                    CHECK_EQ(large_rpc.response_len, decoded_size);
                    if (large_rpc.response_len == decoded_size) {
                        CHECK_EQ(memcmp(large_rpc.response.get(), native.get(), kNativeLen), 0);
                        CHECK_EQ(memcmp(large_rpc.response.get() + kNativeLen,
                                        expected_trailer,
                                        expected_trailer_len),
                                 0);
                    }
                }
                CHECK_EQ(server->last_completed_request_size.load(), kNativeLen);
                CHECK_EQ(server->last_completed_request_hash.load(), native_hash);
                CHECK_EQ(server->last_completed_content_length.load(), 0u);
                if (text) text_cases_completed++;
                CHECK_EQ(server->grpc_content_type_requests.load(),
                         content_types_before + case_index + 1);
                CHECK_EQ(server->te_trailers_requests.load(), te_trailers_before + case_index + 1);
                CHECK_EQ(server->text_marker_requests.load(),
                         text_markers_before + text_cases_completed);
                CHECK_GE(client.window_updates - client_updates_before, 2u);
                CHECK_GE(server->window_updates.load() - server_updates_before, 2u);
            }
            CHECK_EQ(server->grpc_content_type_requests.load(), content_types_before + 4);
            CHECK_EQ(server->te_trailers_requests.load(), te_trailers_before + 4);
            CHECK_EQ(server->bad_web_request_headers.load(), 0u);
            CHECK_EQ(server->text_marker_requests.load(), text_markers_before + 2);
            CHECK_EQ(server->text_content_length_requests.load(), 0u);
        }
    }
    shard->stop();
    shard->join();
    CHECK_EQ(shard->shard_metrics.grpc_started, 15u);
    CHECK_EQ(shard->shard_metrics.grpc_active, 0u);
    CHECK_EQ(shard->shard_metrics.grpc_completed[0], 12u);
    CHECK_EQ(shard->shard_metrics.grpc_completed[7], 1u);
    CHECK_EQ(shard->shard_metrics.grpc_completed[13], 1u);
    CHECK_EQ(shard->shard_metrics.grpc_completed[14], 1u);
    CHECK_EQ(shard->shard_metrics.grpc_latency.count, 15u);
    AccessLogEntry log_entry{};
    u32 large_70k_logs = 0, large_binary_logs = 0, large_text_logs = 0;
    while (shard->log_ring->pop(log_entry)) {
        if (log_entry.req_size == 70005u) {
            large_70k_logs++;
            CHECK_EQ(log_entry.resp_size, 70005u + expected_trailer_size);
        }
        if (log_entry.req_size == 130005u) {
            large_binary_logs++;
            CHECK_EQ(log_entry.resp_size, 130005u + expected_trailer_size);
            CHECK_EQ(log_entry.grpc_status_plus_one, 1u);
        }
        if (log_entry.req_size == 173340u) {
            large_text_logs++;
            CHECK_EQ(log_entry.resp_size, 173396u);
            CHECK_EQ(log_entry.grpc_status_plus_one, 1u);
        }
    }
    CHECK_EQ(large_70k_logs, 1u);
    CHECK_EQ(large_binary_logs, 2u);
    CHECK_EQ(large_text_logs, 2u);
    shard->loop->force_close_all();
    if (shard->loop->listen_fd >= 0) {
        close(shard->loop->listen_fd);
        shard->loop->listen_fd = -1;
    }
    shard->shutdown();
}

TEST(grpc_proxy, grpc_web_h2_epoll) {
    grpc_web_h2_case<EpollEventLoop>(_tc);
}
TEST(grpc_proxy, grpc_web_h2_iouring) {
    grpc_web_h2_case<IoUringEventLoop>(_tc);
}

template <typename Loop>
void grpc_retry_trailers_only_case(rut::test::TestCase* _tc,
                                   u8 mode,
                                   bool web = false,
                                   bool text = false) {
    (void)_tc;
    auto server = std::make_unique<EchoServer>();
    REQUIRE(server->start());
    server->reply_mode = 1;  // First request gets trailers-only UNAUTHENTICATED.
    auto shard = std::make_unique<Shard<Loop>>();
    const int lfd = create_listen_socket(0).value_or(-1);
    REQUIRE(lfd >= 0);
    if (!shard->init(0, lfd).has_value()) {
        close(lfd);
        SKIP("backend unavailable");
    }
    REQUIRE(shard->init_access_log().has_value());
    RouteConfig cfg;
    REQUIRE(cfg.add_upstream("grpc", 0x7f000001, get_port(server->listen_fd)).has_value());
    cfg.upstreams[0].http2 = true;
    if (mode != 0)
        cfg.upstreams[0].grpc_retry = {
            2, mode == 4 ? 1u : 1024u, mode == 2 ? (1u << 14) : (1u << 7), 0};
    REQUIRE(cfg.add_proxy("/test.Echo/", 'P', 0));
    shard->route_config = &cfg;
    REQUIRE(shard->spawn(-1).has_value());
    {
        Client client;
        CHECK(client.init(get_port(lfd)));
        if (client.fd >= 0) {
            const u8 valid_request[] = {0, 0, 0, 0, 3, 0xfa, 0xfb, 0xfc};
            const u8 malformed_request[] = {2, 0, 0, 0, 3, 0xfa, 0xfb, 0xfc};
            const u8* request = mode == 3 ? malformed_request : valid_request;
            const u32 request_len = sizeof(valid_request);
            u8 text_request[32];
            const u8* body = request;
            u32 body_len = request_len;
            if (web && text) {
                GrpcWebBase64Encoder encoder{};
                encoder.init();
                u32 consumed = 0, written = 0, flushed = 0;
                CHECK_EQ(encoder.feed(request,
                                      request_len,
                                      consumed,
                                      text_request,
                                      sizeof(text_request),
                                      written),
                         GrpcWebCodecStatus::Ok);
                CHECK_EQ(
                    encoder.flush(text_request + written, sizeof(text_request) - written, flushed),
                    GrpcWebCodecStatus::Ok);
                body = text_request;
                body_len = written + flushed;
            }
            const int sid = web ? client.request_web(0, body, body_len, text, 2, true)
                                : client.request_native_raw(0, body, body_len);
            CHECK(sid > 0);
            CHECK(client.until(0, true));
            const auto& rpc = client.rpcs[0];
            const bool retried = mode == 1;
            CHECK_EQ(server->requests.load(), retried ? 2u : 1u);
            if (!web) {
                CHECK_EQ(rpc.status, retried ? 0u : 7u);
                CHECK_EQ(rpc.ok, retried);
            } else if (retried) {
                u8 decoded[256];
                u32 decoded_len = 0;
                if (text) {
                    GrpcWebBase64Decoder decoder{};
                    decoder.init();
                    u32 consumed = 0, written = 0;
                    CHECK_EQ(decoder.feed(rpc.response.get(),
                                          rpc.response_len,
                                          consumed,
                                          decoded,
                                          sizeof(decoded),
                                          written),
                             GrpcWebCodecStatus::Ok);
                    CHECK_EQ(consumed, rpc.response_len);
                    CHECK_EQ(decoder.finish(), GrpcWebCodecStatus::Ok);
                    decoded_len = written;
                } else {
                    decoded_len = rpc.response_len;
                    CHECK_LE(decoded_len, sizeof(decoded));
                    if (decoded_len <= sizeof(decoded))
                        memcpy(decoded, rpc.response.get(), decoded_len);
                }
                GrpcWebTrailer trailers[] = {{{"grpc-status", 11}, {"0", 1}},
                                             {{"x-trailer", 9}, {"present", 7}}};
                u8 expected[128];
                u32 expected_len = 0;
                REQUIRE(grpc_web_encode_trailer_envelope(
                    trailers, 2, expected, sizeof(expected), expected_len));
                CHECK_EQ(decoded_len, request_len + expected_len);
                if (decoded_len == request_len + expected_len) {
                    CHECK(memcmp(decoded, request, request_len) == 0);
                    CHECK(memcmp(decoded + request_len, expected, expected_len) == 0);
                }
            }
        }
    }
    shard->stop();
    shard->join();
    CHECK_EQ(shard->shard_metrics.grpc_started, 1u);
    CHECK_EQ(shard->shard_metrics.grpc_active, 0u);
    CHECK_EQ(shard->shard_metrics.grpc_completed[0], mode == 1 ? 1u : 0u);
    CHECK_EQ(shard->shard_metrics.grpc_completed[7], mode == 1 ? 0u : 1u);
    CHECK_EQ(shard->shard_metrics.grpc_latency.count, 1u);
    shard->loop->force_close_all();
    if (shard->loop->listen_fd >= 0) {
        close(shard->loop->listen_fd);
        shard->loop->listen_fd = -1;
    }
    shard->shutdown();
}
TEST(grpc_proxy, grpc_retry_trailers_only_epoll) {
    grpc_retry_trailers_only_case<EpollEventLoop>(_tc, 1);
}
TEST(grpc_proxy, grpc_retry_trailers_only_iouring) {
    grpc_retry_trailers_only_case<IoUringEventLoop>(_tc, 1);
}
TEST(grpc_proxy, grpc_retry_default_off_epoll) {
    grpc_retry_trailers_only_case<EpollEventLoop>(_tc, 0);
}
TEST(grpc_proxy, grpc_retry_default_off_iouring) {
    grpc_retry_trailers_only_case<IoUringEventLoop>(_tc, 0);
}
TEST(grpc_proxy, grpc_retry_nonlisted_status_epoll) {
    grpc_retry_trailers_only_case<EpollEventLoop>(_tc, 2);
}
TEST(grpc_proxy, grpc_retry_nonlisted_status_iouring) {
    grpc_retry_trailers_only_case<IoUringEventLoop>(_tc, 2);
}
TEST(grpc_proxy, grpc_retry_malformed_native_is_transparent) {
    grpc_retry_trailers_only_case<EpollEventLoop>(_tc, 3);
}
TEST(grpc_proxy, grpc_retry_retention_overflow_is_transparent) {
    grpc_retry_trailers_only_case<EpollEventLoop>(_tc, 4);
}
TEST(grpc_proxy, grpc_retry_web_binary_epoll) {
    grpc_retry_trailers_only_case<EpollEventLoop>(_tc, 1, true, false);
}
TEST(grpc_proxy, grpc_retry_web_binary_iouring) {
    grpc_retry_trailers_only_case<IoUringEventLoop>(_tc, 1, true, false);
}
TEST(grpc_proxy, grpc_retry_web_text_epoll) {
    grpc_retry_trailers_only_case<EpollEventLoop>(_tc, 1, true, true);
}
TEST(grpc_proxy, grpc_retry_web_text_iouring) {
    grpc_retry_trailers_only_case<IoUringEventLoop>(_tc, 1, true, true);
}

TEST(grpc_proxy, request_timeout_is_materialized_at_send_time_and_continues_near_cap) {
    GrpcExchange exchange;
    exchange.init();
    exchange.upstream_stream = 1;
    const hpack::Header request[] = {{{":method", 7}, {"POST", 4}},
                                     {{":path", 5}, {"/svc", 4}},
                                     {{"grpc-encoding", 13}, {"gzip", 4}}};
    exchange.request_headers_len =
        http2_write_headers(exchange.request_headers, GrpcExchange::kHeaders, 1, request, 3, false);
    REQUIRE(exchange.request_headers_len > kFrameHeaderSize);
    exchange.timeout_present = true;
    exchange.deadline_us = 10000000;

    u8 output[GrpcExchange::kHeaders + GrpcExchange::kRequestHeadersSlack]{};
    u32 output_len = 0;
    CHECK(grpc_build_request_headers_for_send(
              exchange, 1000000, output, sizeof(output), output_len) ==
          GrpcRequestHeaderBuild::Ready);
    CHECK_GT(output_len, exchange.request_headers_len);
    CHECK_LE(output_len - exchange.request_headers_len, GrpcExchange::kTimeoutFieldMax);
    u8 input[sizeof(output) + kClientPrefaceLen]{};
    __builtin_memcpy(input, kClientPreface, kClientPrefaceLen);
    __builtin_memcpy(input + kClientPrefaceLen, output, output_len);
    Http2Conn parser;
    parser.init();
    GrpcRequestHeaderCapture capture;
    parser.cb_ctx = &capture;
    parser.on_headers = capture_grpc_request_headers;
    u8 control[128]{};
    u32 control_len = 0;
    const auto parsed = parser.process(
        input, kClientPrefaceLen + output_len, control, sizeof(control), &control_len);
    CHECK_FALSE(parsed.close);
    CHECK_EQ(parsed.consumed, kClientPrefaceLen + output_len);
    CHECK_EQ(capture.calls, 1u);
    CHECK_EQ(capture.timeout_count, 1u);
    CHECK_EQ(capture.timeout_len, 8u);
    CHECK_EQ(memcmp(capture.timeout, "9000000u", 8), 0);
    CHECK_EQ(capture.encoding_count, 1u);

    CHECK(grpc_build_request_headers_for_send(
              exchange, 8000000, output, sizeof(output), output_len) ==
          GrpcRequestHeaderBuild::Ready);
    __builtin_memcpy(input, kClientPreface, kClientPrefaceLen);
    __builtin_memcpy(input + kClientPrefaceLen, output, output_len);
    parser.init();
    capture = {};
    parser.cb_ctx = &capture;
    parser.on_headers = capture_grpc_request_headers;
    control_len = 0;
    const auto delayed = parser.process(
        input, kClientPrefaceLen + output_len, control, sizeof(control), &control_len);
    CHECK_FALSE(delayed.close);
    CHECK_EQ(delayed.consumed, kClientPrefaceLen + output_len);
    CHECK_EQ(capture.timeout_count, 1u);
    CHECK_EQ(capture.timeout_len, 8u);
    CHECK_EQ(memcmp(capture.timeout, "2000000u", 8), 0);

    GrpcExchange absent;
    absent.init();
    absent.upstream_stream = 1;
    absent.deadline_us = 100;
    absent.request_headers_len = exchange.request_headers_len;
    __builtin_memcpy(
        absent.request_headers, exchange.request_headers, exchange.request_headers_len);
    CHECK(grpc_build_request_headers_for_send(absent, 200, output, sizeof(output), output_len) ==
          GrpcRequestHeaderBuild::Ready);
    CHECK_EQ(output_len, absent.request_headers_len);
    CHECK_EQ(memcmp(output, absent.request_headers, output_len), 0);

    exchange.deadline_us = 100;
    CHECK(grpc_build_request_headers_for_send(exchange, 100, output, sizeof(output), output_len) ==
          GrpcRequestHeaderBuild::Expired);
    CHECK_EQ(output_len, 0u);

    const hpack::Header duplicate_timeout[] = {{{"grpc-timeout", 12}, {"1S", 2}},
                                               {{"grpc-timeout", 12}, {"2S", 2}}};
    bool timeout_present = false;
    u64 deadline = 0;
    CHECK_FALSE(grpc_request_deadline(duplicate_timeout, 2, 500, timeout_present, deadline));
    const hpack::Header malformed_timeout[] = {{{"grpc-timeout", 12}, {"bad", 3}}};
    CHECK_FALSE(grpc_request_deadline(malformed_timeout, 1, 500, timeout_present, deadline));
    CHECK(grpc_request_deadline(nullptr, 0, 500, timeout_present, deadline));
    CHECK_FALSE(timeout_present);
    CHECK_EQ(deadline, 0u);

    char padding[16350]{};
    hpack::Header near_cap[] = {{{":method", 7}, {"POST", 4}},
                                {{":path", 5}, {"/svc", 4}},
                                {{"x-padding", 9}, {padding, sizeof(padding)}}};
    exchange.init();
    exchange.upstream_stream = 3;
    exchange.timeout_present = true;
    exchange.deadline_us = 10000000;
    char timeout_value[9]{};
    const u32 timeout_value_len = grpc_retry_timeout_value(timeout_value, 9000000);
    u8 timeout_field[GrpcExchange::kTimeoutFieldMax]{};
    const u32 timeout_field_len = hpack::encode_header(
        timeout_field, {"grpc-timeout", 12}, {timeout_value, timeout_value_len});
    u32 near_cap_padding_len = 0;
    u32 exact_fit_padding_len = 0;
    for (u32 candidate = 16'300; candidate < sizeof(padding); ++candidate) {
        near_cap[2].value = {padding, candidate};
        exchange.request_headers_len = http2_write_headers(
            exchange.request_headers, GrpcExchange::kHeaders, 3, near_cap, 3, false);
        Http2FrameHeader base{};
        if (!exchange.request_headers_len ||
            parse_frame_header(exchange.request_headers, exchange.request_headers_len, &base) !=
                ParseStatus::Complete)
            continue;
        if (base.length + timeout_field_len <= kDefaultMaxFrameSize) {
            if (exchange.request_headers_len + timeout_field_len == SlicePool::kSliceSize)
                exact_fit_padding_len = candidate;
            if (exchange.request_headers_len + timeout_field_len > SlicePool::kSliceSize) {
                near_cap_padding_len = candidate;
                break;
            }
        }
    }
    REQUIRE(near_cap_padding_len != 0);
    REQUIRE(exact_fit_padding_len != 0);
    near_cap[2].value = {padding, exact_fit_padding_len};
    exchange.request_headers_len = http2_write_headers(
        exchange.request_headers, GrpcExchange::kHeaders, 3, near_cap, 3, false);
    u8 exact_fit_slice[SlicePool::kSliceSize + 16];
    __builtin_memset(exact_fit_slice, 0xa5, sizeof(exact_fit_slice));
    u8 exact_fit_continuation[GrpcExchange::kRequestHeadersSlack]{};
    u32 exact_fit_written = 0;
    u32 exact_fit_continuation_len = 0;
    CHECK(grpc_build_request_headers_for_send(exchange,
                                              1000000,
                                              exact_fit_slice,
                                              SlicePool::kSliceSize,
                                              exact_fit_written,
                                              exact_fit_continuation,
                                              sizeof(exact_fit_continuation),
                                              exact_fit_continuation_len) ==
          GrpcRequestHeaderBuild::Ready);
    CHECK_EQ(exact_fit_written, SlicePool::kSliceSize);
    CHECK_EQ(exact_fit_continuation_len, 0u);
    for (u32 i = SlicePool::kSliceSize; i < sizeof(exact_fit_slice); ++i)
        CHECK_EQ(exact_fit_slice[i], 0xa5u);
    Http2FrameHeader exact_fit_header{};
    REQUIRE_EQ(parse_frame_header(exact_fit_slice, exact_fit_written, &exact_fit_header),
               ParseStatus::Complete);
    CHECK(exact_fit_header.flags & http2_flag::kEndHeaders);

    near_cap[2].value = {padding, near_cap_padding_len};
    exchange.request_headers_len = http2_write_headers(
        exchange.request_headers, GrpcExchange::kHeaders, 3, near_cap, 3, false);
    REQUIRE(exchange.request_headers_len > GrpcExchange::kHeaders - 64);
    Http2FrameHeader base_headers{};
    REQUIRE_EQ(
        parse_frame_header(exchange.request_headers, exchange.request_headers_len, &base_headers),
        ParseStatus::Complete);
    CHECK_LE(base_headers.length + timeout_field_len, kDefaultMaxFrameSize);
    CHECK_GT(exchange.request_headers_len + timeout_field_len, SlicePool::kSliceSize);
    u8 bounded_slice[SlicePool::kSliceSize + 16];
    __builtin_memset(bounded_slice, 0xa5, sizeof(bounded_slice));
    u8 bounded_continuation[GrpcExchange::kRequestHeadersSlack]{};
    u32 bounded_written = 0;
    u32 bounded_continuation_len = 0;
    CHECK(grpc_build_request_headers_for_send(exchange,
                                              1000000,
                                              bounded_slice,
                                              SlicePool::kSliceSize,
                                              bounded_written,
                                              bounded_continuation,
                                              sizeof(bounded_continuation),
                                              bounded_continuation_len) ==
          GrpcRequestHeaderBuild::Ready);
    CHECK_LE(bounded_written, SlicePool::kSliceSize);
    CHECK_GT(bounded_continuation_len, 0u);
    for (u32 i = SlicePool::kSliceSize; i < sizeof(bounded_slice); ++i)
        CHECK_EQ(bounded_slice[i], 0xa5u);
    u8 bounded_wire[SlicePool::kSliceSize + GrpcExchange::kRequestHeadersSlack]{};
    __builtin_memcpy(bounded_wire, bounded_slice, bounded_written);
    __builtin_memcpy(
        bounded_wire + bounded_written, bounded_continuation, bounded_continuation_len);
    __builtin_memcpy(input, kClientPreface, kClientPrefaceLen);
    __builtin_memcpy(
        input + kClientPrefaceLen, bounded_wire, bounded_written + bounded_continuation_len);
    parser.init();
    capture = {};
    parser.cb_ctx = &capture;
    parser.on_headers = capture_grpc_request_headers;
    control_len = 0;
    const auto bounded_parse =
        parser.process(input,
                       kClientPrefaceLen + bounded_written + bounded_continuation_len,
                       control,
                       sizeof(control),
                       &control_len);
    CHECK_FALSE(bounded_parse.close);
    CHECK_EQ(bounded_parse.consumed,
             kClientPrefaceLen + bounded_written + bounded_continuation_len);
    CHECK_EQ(capture.calls, 1u);
    CHECK_EQ(capture.timeout_count, 1u);
    CHECK_EQ(capture.timeout_len, 8u);
    CHECK_EQ(memcmp(capture.timeout, "9000000u", 8), 0);
    CHECK_EQ(capture.padding_len, near_cap_padding_len);
    Http2FrameHeader bounded_prefix{};
    REQUIRE_EQ(parse_frame_header(bounded_slice, bounded_written, &bounded_prefix),
               ParseStatus::Complete);
    CHECK_FALSE(bounded_prefix.flags & http2_flag::kEndHeaders);
    Http2FrameHeader bounded_cont{};
    REQUIRE_EQ(parse_frame_header(bounded_continuation, bounded_continuation_len, &bounded_cont),
               ParseStatus::Complete);
    CHECK_EQ(bounded_cont.type, static_cast<u8>(Http2FrameType::Continuation));
    CHECK_EQ(bounded_cont.stream_id, 3u);
    CHECK_EQ(bounded_cont.flags, http2_flag::kEndHeaders);
    CHECK_EQ(bounded_continuation_len, kFrameHeaderSize + bounded_cont.length);
    u8 ordinary_send_slice[SlicePool::kSliceSize]{};
    u32 ordinary_send_len = 99;
    CHECK(grpc_build_request_headers_for_send(exchange,
                                              1000000,
                                              ordinary_send_slice,
                                              sizeof(ordinary_send_slice),
                                              ordinary_send_len) ==
          GrpcRequestHeaderBuild::NoSpace);
    CHECK_EQ(ordinary_send_len, 0u);
    ordinary_send_len = 99;
    CHECK(grpc_build_request_headers_for_send(exchange,
                                              1000000,
                                              ordinary_send_slice,
                                              exchange.request_headers_len - 1,
                                              ordinary_send_len) ==
          GrpcRequestHeaderBuild::NoSpace);
    CHECK_EQ(ordinary_send_len, 0u);
    CHECK(grpc_build_request_headers_for_send(
              exchange, 1000000, output, sizeof(output), output_len) ==
          GrpcRequestHeaderBuild::Ready);
    Http2FrameHeader first{};
    REQUIRE_EQ(parse_frame_header(output, output_len, &first), ParseStatus::Complete);
    CHECK_EQ(first.type, static_cast<u8>(Http2FrameType::Headers));
    CHECK(first.flags & http2_flag::kEndHeaders);
    CHECK_LE(first.length, kDefaultMaxFrameSize);
    CHECK_EQ(output_len, exchange.request_headers_len + timeout_field_len);
    __builtin_memcpy(input, kClientPreface, kClientPrefaceLen);
    __builtin_memcpy(input + kClientPrefaceLen, output, output_len);
    parser.init();
    capture = {};
    parser.cb_ctx = &capture;
    parser.on_headers = capture_grpc_request_headers;
    control_len = 0;
    const auto continued = parser.process(
        input, kClientPrefaceLen + output_len, control, sizeof(control), &control_len);
    CHECK_FALSE(continued.close);
    CHECK_EQ(continued.consumed, kClientPrefaceLen + output_len);
    CHECK_EQ(capture.calls, 1u);
    CHECK_EQ(capture.timeout_count, 1u);
    CHECK_EQ(capture.encoding_count, 0u);
    CHECK_EQ(capture.padding_len, near_cap_padding_len);

    exchange.deadline_us = 1'000'000 + 99'999'999ull * 3'600'000'000ull;
    CHECK(grpc_build_request_headers_for_send(
              exchange, 1'000'000, output, sizeof(output), output_len) ==
          GrpcRequestHeaderBuild::Ready);
    CHECK_GT(output_len, exchange.request_headers_len);
    __builtin_memcpy(input, kClientPreface, kClientPrefaceLen);
    __builtin_memcpy(input + kClientPrefaceLen, output, output_len);
    parser.init();
    capture = {};
    parser.cb_ctx = &capture;
    parser.on_headers = capture_grpc_request_headers;
    control_len = 0;
    const auto maximum_timeout = parser.process(
        input, kClientPrefaceLen + output_len, control, sizeof(control), &control_len);
    CHECK_FALSE(maximum_timeout.close);
    CHECK_EQ(maximum_timeout.consumed, kClientPrefaceLen + output_len);
    CHECK_EQ(capture.timeout_count, 1u);
    CHECK_EQ(capture.timeout_len, 9u);
    CHECK_EQ(memcmp(capture.timeout, "99999999H", 9), 0);

    char oversized_value[16'380]{};
    u8 oversized_block[Http2Conn::kHeaderBlockCap]{};
    const u32 oversized_len = hpack::encode_header(
        oversized_block, {"x-padding", 9}, {oversized_value, sizeof(oversized_value)});
    CHECK_GT(oversized_len, Http2Conn::kHeaderScratchCap);
    CHECK_LE(oversized_len, Http2Conn::kHeaderBlockCap);
    u8 oversized_input[kClientPrefaceLen + kFrameHeaderSize + Http2Conn::kHeaderBlockCap]{};
    __builtin_memcpy(oversized_input, kClientPreface, kClientPrefaceLen);
    Http2FrameHeader oversized_headers{};
    oversized_headers.length = oversized_len;
    oversized_headers.type = static_cast<u8>(Http2FrameType::Headers);
    oversized_headers.flags = http2_flag::kEndHeaders;
    oversized_headers.stream_id = 1;
    write_frame_header(oversized_input + kClientPrefaceLen, oversized_headers);
    __builtin_memcpy(
        oversized_input + kClientPrefaceLen + kFrameHeaderSize, oversized_block, oversized_len);
    parser.init();
    control_len = 0;
    const auto overflow = parser.process(oversized_input,
                                         kClientPrefaceLen + kFrameHeaderSize + oversized_len,
                                         control,
                                         sizeof(control),
                                         &control_len);
    CHECK(overflow.close);
}

TEST(grpc_proxy, request_timeout_uses_regular_send_slice_then_continuation) {
    GrpcDriveFixture loop;
    Connection conn;
    conn.reset();
    conn.send_slice = loop.pool.alloc();
    REQUIRE(conn.send_slice != nullptr);
    conn.send_buf.bind(conn.send_slice, SlicePool::kSliceSize);
    Http2Conn h2;
    h2.init_client();
    h2.grpc.upstream = true;
    h2.grpc.connecting = true;
    conn.h2 = &h2;

    GrpcExchange exchange;
    exchange.init();
    exchange.upstream_stream = 1;
    exchange.request_headers_len = GrpcExchange::kHeaders;
    exchange.timeout_present = true;
    exchange.deadline_us = 10'000'000;
    Http2FrameHeader headers{};
    headers.length = GrpcExchange::kHeaders - kFrameHeaderSize;
    headers.type = static_cast<u8>(Http2FrameType::Headers);
    headers.flags = http2_flag::kEndHeaders;
    headers.stream_id = 1;
    write_frame_header(exchange.request_headers, headers);

    u32 written = 0;
    REQUIRE(grpc_build_request_headers_for_send(exchange,
                                                1'000'000,
                                                conn.send_buf.write_ptr(),
                                                conn.send_buf.write_avail(),
                                                written,
                                                h2.grpc.header_continuation,
                                                sizeof(h2.grpc.header_continuation),
                                                h2.grpc.header_continuation_len) ==
            GrpcRequestHeaderBuild::Ready);
    CHECK_EQ(written, SlicePool::kSliceSize);
    CHECK_LE(written, conn.send_buf.capacity());
    conn.send_buf.commit(written);
    Http2FrameHeader first{};
    REQUIRE_EQ(parse_frame_header(conn.send_buf.data(), conn.send_buf.len(), &first),
               ParseStatus::Complete);
    CHECK_EQ(first.type, static_cast<u8>(Http2FrameType::Headers));
    CHECK_FALSE(first.flags & http2_flag::kEndHeaders);
    CHECK_GT(h2.grpc.header_continuation_len, 0u);
    CHECK_LE(h2.grpc.header_continuation_len, sizeof(h2.grpc.header_continuation));

    conn.on_send = &grpc_on_upstream_sent<GrpcDriveFixture>;
    REQUIRE(loop.submit_send(conn, conn.send_buf.data(), conn.send_buf.len()));
    grpc_on_upstream_sent<GrpcDriveFixture>(
        &loop, conn, {conn.id, static_cast<i32>(written), 0, 0, IoEventType::Send, 0});
    CHECK_EQ(loop.sends, 2u);
    CHECK(h2.grpc.header_continuation_sending);
    Http2FrameHeader continuation{};
    REQUIRE_EQ(parse_frame_header(conn.send_buf.data(), conn.send_buf.len(), &continuation),
               ParseStatus::Complete);
    CHECK_EQ(continuation.type, static_cast<u8>(Http2FrameType::Continuation));
    CHECK_EQ(continuation.stream_id, 1u);
    CHECK_EQ(continuation.flags, http2_flag::kEndHeaders);
    grpc_on_upstream_sent<GrpcDriveFixture>(
        &loop, conn, {conn.id, static_cast<i32>(conn.send_buf.len()), 0, 0, IoEventType::Send, 0});
    CHECK_FALSE(h2.grpc.header_continuation_sending);
    CHECK_EQ(h2.grpc.header_continuation_len, 0u);
    CHECK_FALSE(loop.closed);
    loop.pool.free(conn.send_slice);
}

TEST(grpc_proxy, timeout_continuation_submit_failure_closes_connection) {
    GrpcDriveFixture loop;
    Connection conn;
    conn.reset();
    conn.send_slice = loop.pool.alloc();
    REQUIRE(conn.send_slice != nullptr);
    conn.send_buf.bind(conn.send_slice, SlicePool::kSliceSize);
    Http2Conn h2;
    h2.init_client();
    h2.grpc.upstream = true;
    h2.grpc.preface_sent = true;
    h2.peer_settings_seen = true;
    conn.h2 = &h2;

    GrpcExchange exchange;
    exchange.init();
    exchange.upstream = &conn;
    exchange.upstream_stream = 1;
    exchange.timeout_present = true;
    exchange.deadline_us = monotonic_us() + 10'000'000;
    exchange.request_headers_len = GrpcExchange::kHeaders;
    Http2FrameHeader request_headers{};
    request_headers.length = GrpcExchange::kHeaders - kFrameHeaderSize;
    request_headers.type = static_cast<u8>(Http2FrameType::Headers);
    request_headers.flags = http2_flag::kEndHeaders;
    request_headers.stream_id = 1;
    write_frame_header(exchange.request_headers, request_headers);
    REQUIRE(h2.open_stream(1) != nullptr);
    REQUIRE(grpc_attach(h2, &exchange));

    loop.fail_send_on = 2;
    grpc_drive_upstream(&loop, conn);
    CHECK_EQ(loop.sends, 1u);
    CHECK_FALSE(loop.closed);
    grpc_on_upstream_sent<GrpcDriveFixture>(
        &loop, conn, {conn.id, static_cast<i32>(conn.send_buf.len()), 0, 0, IoEventType::Send, 0});
    CHECK_EQ(loop.sends, 2u);
    CHECK(loop.closed);
    CHECK(h2.grpc.header_continuation_sending);
    grpc_detach(h2, &exchange);
    loop.pool.free(conn.send_slice);
}

TEST(grpc_proxy, request_timeout_slice_boundary_drives_split_and_parses_after_partial_sends) {
    GrpcDriveFixture loop;
    Connection conn;
    conn.reset();
    conn.send_slice = loop.pool.alloc();
    REQUIRE(conn.send_slice != nullptr);
    conn.send_buf.bind(conn.send_slice, SlicePool::kSliceSize);
    Http2Conn h2;
    h2.init_client();
    h2.grpc.upstream = true;
    h2.grpc.preface_sent = true;
    h2.peer_settings_seen = true;
    conn.h2 = &h2;

    GrpcExchange exchange;
    exchange.init();
    exchange.upstream = &conn;
    exchange.upstream_stream = 1;
    exchange.timeout_present = true;
    exchange.deadline_us = monotonic_us() + 10'000'000;
    char timeout_value[9]{};
    const u32 timeout_value_len = grpc_retry_timeout_value(timeout_value, 9'000'000);
    u8 timeout_field[GrpcExchange::kTimeoutFieldMax]{};
    const u32 timeout_field_len = hpack::encode_header(
        timeout_field, {"grpc-timeout", 12}, {timeout_value, timeout_value_len});
    char padding[16'350]{};
    hpack::Header headers[] = {{{":method", 7}, {"POST", 4}},
                               {{":path", 5}, {"/svc", 4}},
                               {{"x-padding", 9}, {padding, sizeof(padding)}}};
    bool found_capacity_only_split = false;
    u32 selected_padding_len = 0;
    for (u32 padding_len = 16'300; padding_len < sizeof(padding); ++padding_len) {
        headers[2].value = {padding, padding_len};
        exchange.request_headers_len = http2_write_headers(
            exchange.request_headers, GrpcExchange::kHeaders, 1, headers, 3, false);
        Http2FrameHeader base{};
        if (!exchange.request_headers_len ||
            parse_frame_header(exchange.request_headers, exchange.request_headers_len, &base) !=
                ParseStatus::Complete)
            continue;
        if (base.length + timeout_field_len <= kDefaultMaxFrameSize - 4 &&
            exchange.request_headers_len + timeout_field_len > SlicePool::kSliceSize) {
            found_capacity_only_split = true;
            selected_padding_len = padding_len;
            break;
        }
    }
    REQUIRE(found_capacity_only_split);
    REQUIRE(h2.open_stream(1) != nullptr);
    REQUIRE(grpc_attach(h2, &exchange));

    grpc_drive_upstream(&loop, conn);
    CHECK_EQ(loop.sends, 1u);
    CHECK(exchange.request_headers_sent);
    const u32 prefix_len = conn.send_buf.len();
    CHECK_LE(prefix_len, conn.send_buf.capacity());
    CHECK_EQ(prefix_len, exchange.request_headers_len);
    u8 wire[SlicePool::kSliceSize + GrpcExchange::kRequestHeadersSlack]{};
    __builtin_memcpy(wire, conn.send_buf.data(), prefix_len);
    Http2FrameHeader prefix{};
    REQUIRE_EQ(parse_frame_header(conn.send_buf.data(), prefix_len, &prefix),
               ParseStatus::Complete);
    CHECK_EQ(prefix.type, static_cast<u8>(Http2FrameType::Headers));
    CHECK_FALSE(prefix.flags & http2_flag::kEndHeaders);

    h2.grpc.connecting = true;
    grpc_on_upstream_sent<GrpcDriveFixture>(
        &loop, conn, {conn.id, static_cast<i32>(prefix_len / 2), 0, 0, IoEventType::Send, 0});
    CHECK_EQ(loop.sends, 2u);
    grpc_on_upstream_sent<GrpcDriveFixture>(
        &loop,
        conn,
        {conn.id, static_cast<i32>(prefix_len - prefix_len / 2), 0, 0, IoEventType::Send, 0});
    CHECK_EQ(loop.sends, 3u);
    CHECK(h2.grpc.header_continuation_sending);
    const u32 continuation_len = conn.send_buf.len();
    CHECK_LE(continuation_len, conn.send_buf.capacity());
    __builtin_memcpy(wire + prefix_len, conn.send_buf.data(), continuation_len);
    Http2FrameHeader continuation{};
    REQUIRE_EQ(parse_frame_header(conn.send_buf.data(), continuation_len, &continuation),
               ParseStatus::Complete);
    CHECK_EQ(continuation.type, static_cast<u8>(Http2FrameType::Continuation));
    CHECK_EQ(continuation.stream_id, 1u);
    CHECK_EQ(continuation.flags, http2_flag::kEndHeaders);
    CHECK_EQ(continuation_len, kFrameHeaderSize + continuation.length);

    grpc_on_upstream_sent<GrpcDriveFixture>(
        &loop, conn, {conn.id, static_cast<i32>(continuation_len / 2), 0, 0, IoEventType::Send, 0});
    CHECK_EQ(loop.sends, 4u);
    grpc_on_upstream_sent<GrpcDriveFixture>(
        &loop,
        conn,
        {conn.id,
         static_cast<i32>(continuation_len - continuation_len / 2),
         0,
         0,
         IoEventType::Send,
         0});
    CHECK_FALSE(h2.grpc.header_continuation_sending);
    CHECK_FALSE(loop.closed);

    u8 input[kClientPrefaceLen + sizeof(wire)]{};
    __builtin_memcpy(input, kClientPreface, kClientPrefaceLen);
    __builtin_memcpy(input + kClientPrefaceLen, wire, prefix_len + continuation_len);
    Http2Conn parser;
    parser.init();
    GrpcRequestHeaderCapture capture;
    parser.cb_ctx = &capture;
    parser.on_headers = capture_grpc_request_headers;
    u8 control[128]{};
    u32 control_len = 0;
    const auto parsed = parser.process(input,
                                       kClientPrefaceLen + prefix_len + continuation_len,
                                       control,
                                       sizeof(control),
                                       &control_len);
    CHECK_FALSE(parsed.close);
    CHECK_EQ(parsed.consumed, kClientPrefaceLen + prefix_len + continuation_len);
    CHECK_EQ(capture.calls, 1u);
    CHECK_EQ(capture.timeout_count, 1u);
    CHECK_EQ(capture.timeout_len, 8u);
    CHECK_EQ(capture.timeout[7], 'u');
    CHECK_EQ(capture.padding_len, selected_padding_len);
    grpc_detach(h2, &exchange);
    loop.pool.free(conn.send_slice);
}

TEST(grpc_proxy, keepalive_tick_queues_ping_behind_split_headers_and_before_other_stream_data) {
    GrpcDriveFixture loop;
    Connection conn;
    conn.reset();
    u8 recv_slice[64]{};
    conn.bind_request_receive_buffer(recv_slice, sizeof(recv_slice));
    conn.send_slice = loop.pool.alloc();
    REQUIRE(conn.send_slice != nullptr);
    conn.send_buf.bind(conn.send_slice, SlicePool::kSliceSize);
    Http2Conn h2;
    h2.init_client();
    h2.grpc.upstream = true;
    h2.grpc.preface_sent = true;
    h2.grpc.connected_at_us = monotonic_us() - 300'000'001;
    h2.peer_settings_seen = true;
    conn.h2 = &h2;

    GrpcExchange exchange;
    exchange.init();
    exchange.upstream = &conn;
    exchange.upstream_stream = 1;
    exchange.timeout_present = true;
    exchange.deadline_us = monotonic_us() + 10'000'000;
    char timeout_value[9]{};
    const u32 timeout_value_len = grpc_retry_timeout_value(timeout_value, 9'000'000);
    u8 timeout_field[GrpcExchange::kTimeoutFieldMax]{};
    const u32 timeout_field_len = hpack::encode_header(
        timeout_field, {"grpc-timeout", 12}, {timeout_value, timeout_value_len});
    char padding[16'350]{};
    hpack::Header headers[] = {{{":method", 7}, {"POST", 4}},
                               {{":path", 5}, {"/svc", 4}},
                               {{"x-padding", 9}, {padding, sizeof(padding)}}};
    bool found_capacity_only_split = false;
    for (u32 padding_len = 16'300; padding_len < sizeof(padding); ++padding_len) {
        headers[2].value = {padding, padding_len};
        exchange.request_headers_len = http2_write_headers(
            exchange.request_headers, GrpcExchange::kHeaders, 1, headers, 3, false);
        Http2FrameHeader base{};
        if (!exchange.request_headers_len ||
            parse_frame_header(exchange.request_headers, exchange.request_headers_len, &base) !=
                ParseStatus::Complete)
            continue;
        if (base.length + timeout_field_len <= kDefaultMaxFrameSize - 4 &&
            exchange.request_headers_len + timeout_field_len > SlicePool::kSliceSize) {
            found_capacity_only_split = true;
            break;
        }
    }
    REQUIRE(found_capacity_only_split);
    REQUIRE(h2.open_stream(1) != nullptr);
    REQUIRE(grpc_attach(h2, &exchange));

    grpc_drive_upstream(&loop, conn);
    REQUIRE_EQ(loop.sends, 1u);
    const u32 headers_len = conn.send_buf.len();
    CHECK_EQ(headers_len, exchange.request_headers_len);
    u8 wire[SlicePool::kSliceSize + GrpcExchange::kRequestHeadersSlack + 64]{};
    __builtin_memcpy(wire, conn.send_buf.data(), headers_len);

    GrpcExchange other;
    other.init();
    other.upstream = &conn;
    other.upstream_stream = 3;
    other.request_headers_sent = true;
    other.replaying_attempt = true;
    other.upload_len = 3;
    other.upload[0] = 0;
    other.upload[1] = 0;
    other.upload[2] = 1;
    REQUIRE(h2.open_stream(3) != nullptr);
    REQUIRE(grpc_attach(h2, &other));

    u8 borrowed_snapshot[SlicePool::kSliceSize];
    __builtin_memcpy(borrowed_snapshot, conn.send_buf.data(), headers_len);
    grpc_tick(&loop, conn);
    CHECK_EQ(loop.sends, 1u);
    CHECK_EQ(conn.send_buf.len(), headers_len);
    CHECK_EQ(__builtin_memcmp(borrowed_snapshot, conn.send_buf.data(), headers_len), 0);
    CHECK_EQ(h2.grpc.control_len, kFrameHeaderSize + 8);
    CHECK(h2.ping_pending);

    grpc_on_upstream_sent<GrpcDriveFixture>(
        &loop, conn, {conn.id, static_cast<i32>(headers_len / 2), 0, 0, IoEventType::Send, 0});
    REQUIRE_EQ(loop.sends, 2u);
    const u32 headers_remainder = conn.send_buf.len();
    __builtin_memcpy(borrowed_snapshot, conn.send_buf.data(), headers_remainder);
    grpc_tick(&loop, conn);
    CHECK_EQ(loop.sends, 2u);
    CHECK_EQ(conn.send_buf.len(), headers_remainder);
    CHECK_EQ(__builtin_memcmp(borrowed_snapshot, conn.send_buf.data(), headers_remainder), 0);
    CHECK_EQ(h2.grpc.control_len, kFrameHeaderSize + 8);

    grpc_on_upstream_sent<GrpcDriveFixture>(
        &loop,
        conn,
        {conn.id, static_cast<i32>(headers_len - headers_len / 2), 0, 0, IoEventType::Send, 0});
    REQUIRE_EQ(loop.sends, 3u);
    CHECK(h2.grpc.header_continuation_sending);
    const u32 continuation_len = conn.send_buf.len();
    const u32 continuation_offset = headers_len;
    __builtin_memcpy(wire + continuation_offset, conn.send_buf.data(), continuation_len);
    __builtin_memcpy(borrowed_snapshot, conn.send_buf.data(), continuation_len);
    grpc_tick(&loop, conn);
    CHECK_EQ(loop.sends, 3u);
    CHECK_EQ(conn.send_buf.len(), continuation_len);
    CHECK_EQ(__builtin_memcmp(borrowed_snapshot, conn.send_buf.data(), continuation_len), 0);

    grpc_on_upstream_sent<GrpcDriveFixture>(
        &loop, conn, {conn.id, static_cast<i32>(continuation_len / 2), 0, 0, IoEventType::Send, 0});
    REQUIRE_EQ(loop.sends, 4u);
    const u32 continuation_remainder = conn.send_buf.len();
    __builtin_memcpy(borrowed_snapshot, conn.send_buf.data(), continuation_remainder);
    grpc_tick(&loop, conn);
    CHECK_EQ(loop.sends, 4u);
    CHECK_EQ(conn.send_buf.len(), continuation_remainder);
    CHECK_EQ(__builtin_memcmp(borrowed_snapshot, conn.send_buf.data(), continuation_remainder), 0);

    grpc_on_upstream_sent<GrpcDriveFixture>(
        &loop,
        conn,
        {conn.id,
         static_cast<i32>(continuation_len - continuation_len / 2),
         0,
         0,
         IoEventType::Send,
         0});
    REQUIRE_EQ(loop.sends, 5u);
    CHECK_FALSE(h2.grpc.header_continuation_sending);
    const u32 ping_len = conn.send_buf.len();
    CHECK_EQ(ping_len, kFrameHeaderSize + 8);
    Http2FrameHeader ping{};
    REQUIRE_EQ(parse_frame_header(conn.send_buf.data(), ping_len, &ping), ParseStatus::Complete);
    CHECK_EQ(ping.type, static_cast<u8>(Http2FrameType::Ping));
    CHECK_EQ(ping.stream_id, 0u);
    __builtin_memcpy(wire + continuation_offset + continuation_len, conn.send_buf.data(), ping_len);

    grpc_on_upstream_sent<GrpcDriveFixture>(
        &loop, conn, {conn.id, static_cast<i32>(ping_len), 0, 0, IoEventType::Send, 0});
    REQUIRE_EQ(loop.sends, 6u);
    Http2FrameHeader data{};
    REQUIRE_EQ(parse_frame_header(conn.send_buf.data(), conn.send_buf.len(), &data),
               ParseStatus::Complete);
    CHECK_EQ(data.type, static_cast<u8>(Http2FrameType::Data));
    CHECK_EQ(data.stream_id, 3u);

    u8 input[kClientPrefaceLen + sizeof(wire)]{};
    __builtin_memcpy(input, kClientPreface, kClientPrefaceLen);
    const u32 request_wire_len = headers_len + continuation_len + ping_len;
    __builtin_memcpy(input + kClientPrefaceLen, wire, request_wire_len);
    Http2Conn parser;
    parser.init();
    GrpcRequestHeaderCapture capture;
    parser.cb_ctx = &capture;
    parser.on_headers = capture_grpc_request_headers;
    u8 control[128]{};
    u32 control_len = 0;
    const auto parsed = parser.process(
        input, kClientPrefaceLen + request_wire_len, control, sizeof(control), &control_len);
    CHECK_FALSE(parsed.close);
    CHECK_EQ(parsed.consumed, kClientPrefaceLen + request_wire_len);
    CHECK_EQ(capture.calls, 1u);
    CHECK_EQ(capture.timeout_count, 1u);
    CHECK_GE(control_len, kFrameHeaderSize + 8);
    u32 ack_offset = 0;
    Http2FrameHeader ack{};
    while (ack_offset + kFrameHeaderSize <= control_len) {
        if (parse_frame_header(control + ack_offset, control_len - ack_offset, &ack) !=
            ParseStatus::Complete)
            break;
        if (ack.type == static_cast<u8>(Http2FrameType::Ping) && (ack.flags & http2_flag::kAck))
            break;
        ack_offset += kFrameHeaderSize + ack.length;
    }
    REQUIRE_LT(ack_offset, control_len);
    CHECK_EQ(ack.type, static_cast<u8>(Http2FrameType::Ping));
    CHECK(ack.flags & http2_flag::kAck);
    CHECK_EQ(ack_offset + kFrameHeaderSize + ack.length, control_len);
    CHECK_EQ(ack.length, 8u);
    CHECK_EQ(__builtin_memcmp(control + ack_offset + kFrameHeaderSize,
                              wire + continuation_offset + continuation_len + kFrameHeaderSize,
                              8),
             0);

    u8 ignored[32]{};
    u32 ignored_len = 0;
    const u32 ack_len = kFrameHeaderSize + ack.length;
    const auto acked =
        h2.process(control + ack_offset, ack_len, ignored, sizeof(ignored), &ignored_len);
    CHECK_FALSE(acked.close);
    CHECK_FALSE(h2.ping_pending);

    grpc_detach(h2, &other);
    grpc_detach(h2, &exchange);
    loop.pool.free(conn.send_slice);
}

TEST(grpc_proxy, timeout_continuation_follows_control_and_precedes_other_streams) {
    GrpcDriveFixture loop;
    Connection conn;
    conn.reset();
    conn.send_slice = loop.pool.alloc();
    REQUIRE(conn.send_slice != nullptr);
    conn.send_buf.bind(conn.send_slice, SlicePool::kSliceSize);
    Http2Conn h2;
    h2.init_client();
    h2.grpc.upstream = true;
    h2.grpc.preface_sent = true;
    h2.grpc.connecting = false;
    h2.peer_settings_seen = true;
    conn.h2 = &h2;
    GrpcExchange large;
    large.init();
    large.upstream = &conn;
    large.upstream_stream = 1;
    large.timeout_present = true;
    large.deadline_us = monotonic_us() + 10'000'000;
    large.request_headers_len = GrpcExchange::kHeaders;
    Http2FrameHeader first_headers{};
    first_headers.length = GrpcExchange::kHeaders - kFrameHeaderSize;
    first_headers.type = static_cast<u8>(Http2FrameType::Headers);
    first_headers.flags = http2_flag::kEndHeaders;
    first_headers.stream_id = 1;
    write_frame_header(large.request_headers, first_headers);
    GrpcExchange other;
    other.init();
    other.upstream = &conn;
    other.upstream_stream = 3;
    const hpack::Header simple[] = {{{":method", 7}, {"POST", 4}}, {{":path", 5}, {"/other", 6}}};
    other.request_headers_len =
        http2_write_headers(other.request_headers, GrpcExchange::kHeaders, 3, simple, 2, false);
    REQUIRE(other.request_headers_len > 0);
    REQUIRE(h2.open_stream(1) != nullptr);
    REQUIRE(h2.open_stream(3) != nullptr);
    REQUIRE(grpc_attach(h2, &large));
    REQUIRE(grpc_attach(h2, &other));
    h2.grpc.control_len = write_settings_ack(h2.grpc.control);

    // The driver only builds request headers after all queued control bytes have
    // completed and the shared send slice has been reset to full capacity.
    CHECK_EQ(conn.send_buf.len(), 0u);
    CHECK_EQ(conn.send_buf.write_avail(), SlicePool::kSliceSize);
    grpc_drive_upstream(&loop, conn);
    CHECK_EQ(loop.sends, 1u);
    CHECK_FALSE(large.request_headers_sent);
    Http2FrameHeader ack{};
    REQUIRE_EQ(parse_frame_header(conn.send_buf.data(), conn.send_buf.len(), &ack),
               ParseStatus::Complete);
    CHECK_EQ(ack.type, static_cast<u8>(Http2FrameType::Settings));
    CHECK_EQ(ack.flags, http2_flag::kAck);
    h2.grpc.connecting = true;
    grpc_on_upstream_sent<GrpcDriveFixture>(
        &loop, conn, {conn.id, static_cast<i32>(conn.send_buf.len()), 0, 0, IoEventType::Send, 0});
    CHECK_EQ(conn.send_buf.len(), 0u);
    CHECK_EQ(conn.send_buf.write_avail(), SlicePool::kSliceSize);

    h2.grpc.connecting = false;
    grpc_drive_upstream(&loop, conn);
    CHECK_EQ(loop.sends, 2u);
    CHECK(large.request_headers_sent);
    CHECK_FALSE(other.request_headers_sent);
    Http2FrameHeader initial{};
    REQUIRE_EQ(parse_frame_header(conn.send_buf.data(), conn.send_buf.len(), &initial),
               ParseStatus::Complete);
    CHECK_EQ(initial.type, static_cast<u8>(Http2FrameType::Headers));
    CHECK_FALSE(initial.flags & http2_flag::kEndHeaders);

    const u32 initial_len = conn.send_buf.len();
    grpc_on_upstream_sent<GrpcDriveFixture>(
        &loop, conn, {conn.id, static_cast<i32>(initial_len / 2), 0, 0, IoEventType::Send, 0});
    CHECK_EQ(loop.sends, 3u);
    grpc_on_upstream_sent<GrpcDriveFixture>(
        &loop,
        conn,
        {conn.id, static_cast<i32>(initial_len - initial_len / 2), 0, 0, IoEventType::Send, 0});
    CHECK_EQ(loop.sends, 4u);
    CHECK_FALSE(other.request_headers_sent);
    Http2FrameHeader continuation{};
    REQUIRE_EQ(parse_frame_header(conn.send_buf.data(), conn.send_buf.len(), &continuation),
               ParseStatus::Complete);
    CHECK_EQ(continuation.type, static_cast<u8>(Http2FrameType::Continuation));
    CHECK_EQ(continuation.stream_id, 1u);
    CHECK_EQ(continuation.flags, http2_flag::kEndHeaders);

    const u32 continuation_len = conn.send_buf.len();
    grpc_on_upstream_sent<GrpcDriveFixture>(
        &loop, conn, {conn.id, static_cast<i32>(continuation_len / 2), 0, 0, IoEventType::Send, 0});
    CHECK_EQ(loop.sends, 5u);
    h2.grpc.connecting = true;
    grpc_on_upstream_sent<GrpcDriveFixture>(
        &loop,
        conn,
        {conn.id,
         static_cast<i32>(continuation_len - continuation_len / 2),
         0,
         0,
         IoEventType::Send,
         0});
    CHECK_EQ(loop.sends, 5u);
    CHECK_FALSE(h2.grpc.header_continuation_sending);
    CHECK_FALSE(other.request_headers_sent);

    grpc_drive_upstream(&loop, conn);
    CHECK_EQ(loop.sends, 5u);
    h2.grpc.connecting = false;
    grpc_drive_upstream(&loop, conn);
    CHECK_EQ(loop.sends, 6u);
    CHECK(other.request_headers_sent);
    Http2FrameHeader other_headers{};
    REQUIRE_EQ(parse_frame_header(conn.send_buf.data(), conn.send_buf.len(), &other_headers),
               ParseStatus::Complete);
    CHECK_EQ(other_headers.type, static_cast<u8>(Http2FrameType::Headers));
    CHECK_EQ(other_headers.stream_id, 3u);
    grpc_detach(h2, &large);
    grpc_detach(h2, &other);
    loop.pool.free(conn.send_slice);
}

TEST(grpc_proxy, request_timeout_waits_for_connect_tls_settings_and_stream_slot) {
    GrpcDriveFixture loop;
    REQUIRE(loop.pool_ready);
    Connection upstream;
    upstream.reset();
    u8 upstream_send[SlicePool::kSliceSize]{};
    upstream.send_slice = upstream_send;
    upstream.send_buf.bind(upstream_send, sizeof(upstream_send));
    Http2Conn upstream_h2;
    upstream_h2.init_client();
    upstream_h2.grpc.upstream = true;
    upstream_h2.grpc.preface_sent = true;
    upstream_h2.grpc.connecting = true;
    upstream_h2.grpc.client_tls.ssl_ctx = reinterpret_cast<SSL_CTX*>(1);
    upstream.h2 = &upstream_h2;

    Connection downstream;
    downstream.reset();
    Http2Conn downstream_h2;
    downstream_h2.init_client();
    downstream_h2.grpc.busy = true;
    downstream.h2 = &downstream_h2;
    REQUIRE(upstream_h2.open_stream(1) != nullptr);
    REQUIRE(downstream_h2.open_stream(1) != nullptr);
    auto* exchange = reinterpret_cast<GrpcExchange*>(loop.pool.alloc_bulk());
    REQUIRE(exchange != nullptr);
    exchange->init();
    exchange->downstream = &downstream;
    exchange->upstream = &upstream;
    exchange->downstream_stream = exchange->upstream_stream = 1;
    exchange->timeout_present = true;
    exchange->deadline_us = monotonic_us() + 10000000;
    const hpack::Header request[] = {{{":method", 7}, {"POST", 4}},
                                     {{":path", 5}, {"/svc", 4}},
                                     {{"grpc-encoding", 13}, {"gzip", 4}}};
    exchange->request_headers_len = http2_write_headers(
        exchange->request_headers, GrpcExchange::kHeaders, 1, request, 3, false);
    REQUIRE(exchange->request_headers_len > 0);
    REQUIRE(grpc_attach(upstream_h2, exchange));
    REQUIRE(grpc_attach(downstream_h2, exchange));

    grpc_drive_upstream(&loop, upstream);
    CHECK_EQ(loop.sends, 0u);
    CHECK_FALSE(exchange->request_headers_sent);

    upstream_h2.grpc.connecting = false;
    grpc_drive_upstream(&loop, upstream);
    CHECK_EQ(loop.sends, 0u);
    CHECK_FALSE(exchange->request_headers_sent);

    upstream_h2.grpc.tls_verified = true;
    grpc_drive_upstream(&loop, upstream);
    CHECK_EQ(loop.sends, 0u);
    CHECK_FALSE(exchange->request_headers_sent);

    upstream_h2.peer_settings_seen = true;
    upstream_h2.peer_settings.has_max_concurrent_streams = true;
    upstream_h2.peer_settings.max_concurrent_streams = 0;
    grpc_drive_upstream(&loop, upstream);
    CHECK_EQ(loop.sends, 0u);
    CHECK_FALSE(exchange->request_headers_sent);

    upstream_h2.peer_settings.max_concurrent_streams = 1;
    grpc_drive_upstream(&loop, upstream);
    CHECK_EQ(loop.sends, 1u);
    CHECK(exchange->request_headers_sent);
    CHECK_GT(upstream.send_buf.len(), exchange->request_headers_len);
    u8 input[SlicePool::kSliceSize + kClientPrefaceLen]{};
    __builtin_memcpy(input, kClientPreface, kClientPrefaceLen);
    __builtin_memcpy(input + kClientPrefaceLen, upstream.send_buf.data(), upstream.send_buf.len());
    Http2Conn parser;
    parser.init();
    GrpcRequestHeaderCapture capture;
    parser.cb_ctx = &capture;
    parser.on_headers = capture_grpc_request_headers;
    u8 control[128]{};
    u32 control_len = 0;
    const auto parsed = parser.process(
        input, kClientPrefaceLen + upstream.send_buf.len(), control, sizeof(control), &control_len);
    CHECK_FALSE(parsed.close);
    CHECK_EQ(capture.calls, 1u);
    CHECK_EQ(capture.timeout_count, 1u);
    CHECK_EQ(capture.encoding_count, 1u);

    grpc_detach(upstream_h2, exchange);
    grpc_detach(downstream_h2, exchange);
    loop.pool.free(reinterpret_cast<u8*>(exchange));
}

TEST(grpc_proxy, coarse_deadline_completes_pending_retry_and_releases_slot) {
    GrpcDriveFixture loop;
    REQUIRE(loop.pool_ready);
    Connection upstream;
    upstream.reset();
    Http2Conn upstream_h2;
    upstream_h2.init_client();
    upstream_h2.grpc.upstream = true;
    upstream_h2.grpc.busy = true;
    upstream.h2 = &upstream_h2;
    REQUIRE(upstream_h2.open_stream(1) != nullptr);

    Connection downstream;
    downstream.reset();
    u8 downstream_send[SlicePool::kSliceSize]{};
    u8 downstream_recv[SlicePool::kSliceSize]{};
    downstream.send_slice = downstream_send;
    downstream.send_buf.bind(downstream_send, sizeof(downstream_send));
    downstream.bind_request_receive_buffer(downstream_recv, sizeof(downstream_recv));
    Http2Conn downstream_h2;
    downstream_h2.init_client();
    downstream.h2 = &downstream_h2;
    REQUIRE(downstream_h2.open_stream(1) != nullptr);

    auto* exchange = reinterpret_cast<GrpcExchange*>(loop.pool.alloc_bulk());
    REQUIRE(exchange != nullptr);
    exchange->init();
    exchange->downstream = &downstream;
    exchange->upstream = &upstream;
    exchange->downstream_stream = exchange->upstream_stream = 1;
    exchange->upstream_id = 0;
    exchange->retry_pending = true;
    exchange->retry_at_us = monotonic_us() - 1;
    exchange->deadline_us = monotonic_us() - 1;
    exchange->request_end = exchange->request_end_sent = true;
    exchange->request_headers_sent = true;
    exchange->slot_held = true;
    REQUIRE(grpc_attach(upstream_h2, exchange));
    REQUIRE(grpc_attach(downstream_h2, exchange));

    grpc_tick(&loop, downstream);

    CHECK_EQ(loop.downstream_sends, 1u);
    CHECK_EQ(loop.released, 1u);
    CHECK_EQ(downstream_h2.grpc.active, 0u);
    CHECK_EQ(upstream_h2.grpc.active, 0u);
    CHECK_EQ(downstream_h2.grpc.timer_deadline_us, 0u);
    Http2FrameHeader response{};
    REQUIRE_EQ(parse_frame_header(downstream.send_buf.data(), downstream.send_buf.len(), &response),
               ParseStatus::Complete);
    CHECK_EQ(response.type, static_cast<u8>(Http2FrameType::Headers));
    hpack::DynamicTable dynamic;
    dynamic.init(0);
    u8 decoded_storage[128]{};
    hpack::Header decoded[8];
    u32 decoded_count = 0;
    REQUIRE(hpack::decode_header_block(dynamic,
                                       downstream.send_buf.data() + kFrameHeaderSize,
                                       response.length,
                                       decoded_storage,
                                       sizeof(decoded_storage),
                                       decoded,
                                       8,
                                       &decoded_count));
    bool deadline_exceeded = false;
    for (u32 i = 0; i < decoded_count; i++)
        if (decoded[i].name.eq({"grpc-status", 11}))
            deadline_exceeded = decoded[i].value.eq({"4", 1});
    CHECK(deadline_exceeded);
}

TEST(grpc_proxy, expired_request_timeout_returns_deadline_exceeded_and_releases_once) {
    GrpcDriveFixture loop;
    REQUIRE(loop.pool_ready);
    Connection upstream;
    upstream.reset();
    u8 upstream_send[SlicePool::kSliceSize]{};
    upstream.send_slice = upstream_send;
    upstream.send_buf.bind(upstream_send, sizeof(upstream_send));
    Http2Conn upstream_h2;
    upstream_h2.init_client();
    upstream_h2.grpc.upstream = true;
    upstream_h2.grpc.preface_sent = true;
    upstream_h2.peer_settings_seen = true;
    upstream.h2 = &upstream_h2;

    Connection downstream;
    downstream.reset();
    u8 downstream_send[SlicePool::kSliceSize]{};
    u8 downstream_recv[SlicePool::kSliceSize]{};
    downstream.send_slice = downstream_send;
    downstream.send_buf.bind(downstream_send, sizeof(downstream_send));
    downstream.bind_request_receive_buffer(downstream_recv, sizeof(downstream_recv));
    Http2Conn downstream_h2;
    downstream_h2.init_client();
    downstream.h2 = &downstream_h2;
    REQUIRE(upstream_h2.open_stream(1) != nullptr);
    REQUIRE(upstream_h2.open_stream(3) != nullptr);
    REQUIRE(downstream_h2.open_stream(1) != nullptr);
    REQUIRE(downstream_h2.open_stream(3) != nullptr);
    auto* exchange = reinterpret_cast<GrpcExchange*>(loop.pool.alloc_bulk());
    REQUIRE(exchange != nullptr);
    exchange->init();
    exchange->downstream = &downstream;
    exchange->upstream = &upstream;
    exchange->downstream_stream = exchange->upstream_stream = 1;
    exchange->timeout_present = true;
    exchange->deadline_us = monotonic_us() - 1;
    exchange->request_end = true;
    exchange->slot_held = true;
    exchange->upstream_id = 3;
    const hpack::Header request[] = {{{":method", 7}, {"POST", 4}}, {{":path", 5}, {"/svc", 4}}};
    exchange->request_headers_len = http2_write_headers(
        exchange->request_headers, GrpcExchange::kHeaders, 1, request, 2, false);
    REQUIRE(exchange->request_headers_len > 0);
    REQUIRE(grpc_attach(upstream_h2, exchange));
    REQUIRE(grpc_attach(downstream_h2, exchange));

    auto* queued = reinterpret_cast<GrpcExchange*>(loop.pool.alloc_bulk());
    REQUIRE(queued != nullptr);
    queued->init();
    queued->downstream = &downstream;
    queued->upstream = &upstream;
    queued->downstream_stream = queued->upstream_stream = 3;
    queued->timeout_present = true;
    queued->deadline_us = monotonic_us() + 60'000'000;
    queued->request_end = true;
    queued->slot_held = true;
    queued->upstream_id = 3;
    queued->request_headers_len =
        http2_write_headers(queued->request_headers, GrpcExchange::kHeaders, 3, request, 2, false);
    REQUIRE(queued->request_headers_len > kFrameHeaderSize);
    u8 queued_output[GrpcExchange::kHeaders + GrpcExchange::kRequestHeadersSlack]{};
    u32 queued_output_len = 0;
    CHECK(grpc_build_request_headers_for_send(
              *queued, monotonic_us(), queued_output, sizeof(queued_output), queued_output_len) ==
          GrpcRequestHeaderBuild::Ready);
    CHECK(upstream_h2.peer_settings_seen);
    CHECK_FALSE(upstream_h2.grpc.connecting);
    CHECK_FALSE(upstream_h2.grpc.busy);
    CHECK(upstream.on_send == nullptr);
    CHECK(upstream_h2.find_stream(3) != nullptr);
    REQUIRE(grpc_attach(upstream_h2, queued));
    REQUIRE(grpc_attach(downstream_h2, queued));

    grpc_drive_upstream(&loop, upstream);

    CHECK_EQ(loop.sends, 2u);
    CHECK_EQ(loop.downstream_sends, 1u);
    CHECK_EQ(loop.sends - loop.downstream_sends, 1u);
    CHECK(queued->request_headers_sent);
    CHECK_EQ(loop.released, 1u);
    CHECK_EQ(upstream_h2.grpc.active, 1u);
    CHECK_EQ(downstream_h2.grpc.active, 1u);
    Http2FrameHeader sent_request{};
    REQUIRE_EQ(parse_frame_header(upstream.send_buf.data(), upstream.send_buf.len(), &sent_request),
               ParseStatus::Complete);
    CHECK_EQ(sent_request.type, static_cast<u8>(Http2FrameType::Headers));
    CHECK_EQ(sent_request.stream_id, 3u);
    Http2FrameHeader response{};
    REQUIRE_EQ(parse_frame_header(downstream.send_buf.data(), downstream.send_buf.len(), &response),
               ParseStatus::Complete);
    CHECK_EQ(response.type, static_cast<u8>(Http2FrameType::Headers));
    hpack::DynamicTable dynamic;
    dynamic.init(0);
    u8 decoded_storage[128]{};
    hpack::Header decoded[8];
    u32 decoded_count = 0;
    REQUIRE(hpack::decode_header_block(dynamic,
                                       downstream.send_buf.data() + kFrameHeaderSize,
                                       response.length,
                                       decoded_storage,
                                       sizeof(decoded_storage),
                                       decoded,
                                       8,
                                       &decoded_count));
    bool unavailable = false;
    for (u32 i = 0; i < decoded_count; ++i)
        if (decoded[i].name.eq({"grpc-status", 11})) unavailable = decoded[i].value.eq({"4", 1});
    CHECK(unavailable);
}

TEST(grpc_proxy, grpc_retry_single_endpoint_refused_then_recovers) {
    auto server = std::make_unique<EchoServer>();
    REQUIRE(server->start());
    server->reply_mode = 10;
    auto shard = std::make_unique<Shard<EpollEventLoop>>();
    const int lfd = create_listen_socket(0).value_or(-1);
    REQUIRE(lfd >= 0);
    if (!shard->init(0, lfd)) {
        close(lfd);
        SKIP("backend unavailable");
    }
    RouteConfig cfg;
    REQUIRE(cfg.add_upstream("grpc", 0x7f000001, get_port(server->listen_fd)));
    cfg.upstreams[0].http2 = true;
    cfg.upstreams[0].grpc_retry = {2, 1024, 1u << 14, 20};
    REQUIRE(cfg.add_proxy("/test.Echo/", 'P', 0));
    shard->route_config = &cfg;
    REQUIRE(shard->spawn(-1));
    {
        Client client;
        CHECK(client.init(get_port(lfd)));
        if (client.fd >= 0) {
            // Compression flag and payload stay opaque through the initial
            // attempt and replay; the encoding metadata is replayed too.
            static constexpr u8 request[] = {1, 0, 0, 0, 1, 0x5a};
            CHECK_EQ(client.request_native_raw(0, request, sizeof(request), "1H", "gzip"), 1);
            CHECK(client.until(0, true));
            CHECK(client.rpcs[0].ok);
            CHECK_EQ(client.rpcs[0].response_len, sizeof(request));
            CHECK_EQ(memcmp(client.rpcs[0].response.get(), request, sizeof(request)), 0);
            CHECK_EQ(server->requests.load(), 2u);
            CHECK_EQ(server->accepts.load(), 1u);
            CHECK_EQ(server->grpc_encoding_requests.load(), 2u);
            CHECK_EQ(server->grpc_timeout_requests.load(), 2u);
            CHECK_GT(server->last_grpc_timeout_us.load(), 0u);
            CHECK_LT(server->last_grpc_timeout_us.load(), 3600000000ull);
            u64 request_hash = 14695981039346656037ull;
            for (u8 byte : request) {
                request_hash ^= byte;
                request_hash *= 1099511628211ull;
            }
            CHECK_EQ(server->last_completed_request_size.load(), sizeof(request));
            CHECK_EQ(server->last_completed_request_hash.load(), request_hash);
        }
    }
    shard->stop();
    shard->join();
    CHECK_EQ(shard->shard_metrics.grpc_started, 1u);
    CHECK_EQ(shard->shard_metrics.grpc_active, 0u);
    CHECK_EQ(shard->shard_metrics.grpc_completed[0], 1u);
    CHECK_EQ(shard->shard_metrics.grpc_latency.count, 1u);
    shard->loop->force_close_all();
    if (shard->loop->listen_fd >= 0) {
        close(shard->loop->listen_fd);
        shard->loop->listen_fd = -1;
    }
    shard->shutdown();
}

TEST(grpc_proxy, grpc_retry_max_three_uses_two_backend_sessions) {
    auto failing_server = std::make_unique<EchoServer>();
    auto recovery_server = std::make_unique<EchoServer>();
    REQUIRE(failing_server->start());
    REQUIRE(recovery_server->start());
    failing_server->reply_mode = 1;
    recovery_server->reply_mode = 1;
    auto shard = std::make_unique<Shard<EpollEventLoop>>();
    const int lfd = create_listen_socket(0).value_or(-1);
    REQUIRE(lfd >= 0);
    if (!shard->init(0, lfd)) {
        close(lfd);
        SKIP("backend unavailable");
    }
    RouteConfig cfg;
    const u32 first_backend = select_backend(0, 2, monotonic_us());
    const u32 second_backend = select_backend(0, 2, monotonic_us());
    CHECK_EQ(second_backend, 1u - first_backend);
    const u16 ports[2] = {first_backend == 0 ? get_port(failing_server->listen_fd)
                                             : get_port(recovery_server->listen_fd),
                          first_backend == 1 ? get_port(failing_server->listen_fd)
                                             : get_port(recovery_server->listen_fd)};
    REQUIRE(cfg.add_upstream("grpc", 0x7f000001, ports[0]));
    REQUIRE(cfg.upstreams[0].add_addr(0x7f000001, ports[1]));
    cfg.upstreams[0].http2 = true;
    cfg.upstreams[0].grpc_retry = {3, 1024, 1u << 7, 0};
    REQUIRE(cfg.add_proxy("/test.Echo/", 'P', 0));
    shard->route_config = &cfg;
    REQUIRE(shard->spawn(-1));
    {
        Client client;
        CHECK(client.init(get_port(lfd)));
        if (client.fd >= 0) {
            static constexpr u8 request[] = {0, 0, 0, 0, 1, 0x5a};
            CHECK_EQ(client.request_native_raw(0, request, sizeof(request)), 1);
            CHECK(client.until(0, true));
            CHECK(client.rpcs[0].ok);
            CHECK_EQ(failing_server->requests.load() + recovery_server->requests.load(), 3u);
            CHECK(
                (failing_server->requests.load() == 2u && recovery_server->requests.load() == 1u) ||
                (failing_server->requests.load() == 1u && recovery_server->requests.load() == 2u));
            CHECK_EQ(failing_server->accepts.load(), 1u);
            CHECK_EQ(recovery_server->accepts.load(), 1u);
        }
    }
    shard->stop();
    shard->join();
    CHECK_EQ(shard->shard_metrics.grpc_started, 1u);
    CHECK_EQ(shard->shard_metrics.grpc_active, 0u);
    CHECK_EQ(shard->shard_metrics.grpc_completed[0], 1u);
    CHECK_EQ(shard->shard_metrics.grpc_latency.count, 1u);
    auto* first = shard->loop->grpc_upstreams;
    REQUIRE(first != nullptr);
    auto* second = first->h2->grpc.pool_next;
    REQUIRE(second != nullptr);
    CHECK_NE(first->upstream_backend_idx, second->upstream_backend_idx);
    CHECK_EQ(second->h2->grpc.pool_next, nullptr);
    shard->loop->force_close_all();
    if (shard->loop->listen_fd >= 0) {
        close(shard->loop->listen_fd);
        shard->loop->listen_fd = -1;
    }
    shard->shutdown();
}

TEST(grpc_proxy, grpc_retry_backend_selection_uses_round_robin_and_skips_tried_ejected) {
    GrpcBackendHealthReset health_reset{};
    constexpr u32 kBackendCount = 4;
    constexpr u16 kStartBackend = 2;
    const u64 now = monotonic_us();
    u32 next_backend = 0;
    do {
        const u32 selected = select_backend(0, kBackendCount, now);
        next_backend = (selected + 1) % kBackendCount;
    } while (next_backend != kStartBackend);
    auto* ejected = backend_health(0, 3);
    REQUIRE(ejected != nullptr);
    ejected->active_down = true;

    RetrySelectionFixture loop;
    REQUIRE(loop.pool_ready);
    RouteConfig cfg;
    REQUIRE(cfg.add_upstream("grpc", 0x7f000001, 1));
    for (u32 i = 1; i < kBackendCount; i++) REQUIRE(cfg.upstreams[0].add_addr(0x7f000001, 1));
    cfg.upstreams[0].http2 = true;
    cfg.upstreams[0].grpc_retry = {4, 1024, 1u << 7, 0};

    Connection downstream;
    downstream.reset();
    Http2Conn downstream_h2;
    downstream_h2.init_client();
    downstream.h2 = &downstream_h2;
    REQUIRE(downstream_h2.open_stream(1) != nullptr);

    GrpcExchange exchange;
    exchange.init();
    exchange.downstream = &downstream;
    exchange.downstream_stream = 1;
    exchange.config_epoch = &cfg;
    exchange.upstream_id = 0;
    exchange.retry_policy = cfg.upstreams[0].grpc_retry;
    exchange.retry_enabled = true;
    exchange.retry_attempts = 3;
    exchange.retry_pending = true;
    exchange.retry_tried_mask = static_cast<u8>((1u << 0) | (1u << 2));
    REQUIRE(exchange.replay_body.init(1024));
    REQUIRE(exchange.replay_body.seal());
    const hpack::Header headers[] = {{{":method", 7}, {"POST", 4}}, {{":path", 5}, {"/svc", 4}}};
    REQUIRE(exchange.replay_headers.capture(headers, 2));
    REQUIRE(exchange.replay_trailers.capture(nullptr, 0));
    REQUIRE(grpc_attach(downstream_h2, &exchange));

    REQUIRE(grpc_bind_retry_attempt(&loop, exchange, now));
    CHECK_EQ(loop.retry_conn.upstream_backend_idx, 1u);
    CHECK_EQ(exchange.retry_tried_mask, static_cast<u8>((1u << 0) | (1u << 1) | (1u << 2)));
    CHECK_EQ(loop.retry_conn.h2->grpc.connect_tried_mask, static_cast<u8>(0x07));
    CHECK_EQ(exchange.retry_attempts, 4u);

    grpc_detach(loop.retry_h2, &exchange);
    grpc_detach(downstream_h2, &exchange);
    exchange.upstream = nullptr;
    exchange.replay_body.release();
    loop.grpc_upstreams = nullptr;
    loop.retry_conn.on_close = nullptr;
    if (loop.retry_conn.fd >= 0) close(loop.retry_conn.fd);
    loop.retry_conn.fd = loop.retry_conn.upstream_fd = -1;
    if (loop.retry_conn.recv_slice) loop.pool.free(loop.retry_conn.recv_slice);
}

TEST(grpc_proxy, grpc_retry_connect_failover_skips_prior_rpc_backends) {
    GrpcBackendHealthReset health_reset{};
    RetryCloseSelectionFixture loop;
    REQUIRE(loop.pool_ready);
    RouteConfig cfg;
    REQUIRE(cfg.add_upstream("grpc", 0x7f000001, 1));
    for (u32 i = 1; i < 5; i++) REQUIRE(cfg.upstreams[0].add_addr(0x7f000001, 1));
    cfg.upstreams[0].http2 = true;
    cfg.upstreams[0].grpc_retry = {3, 1024, 1u << 7, 0};

    const u64 now = monotonic_us();
    u32 selected;
    do {
        selected = select_backend(0, 5, now);
    } while (selected != 1);

    Connection downstream;
    downstream.reset();
    Http2Conn downstream_h2;
    downstream_h2.init_client();
    downstream.h2 = &downstream_h2;
    REQUIRE(downstream_h2.open_stream(1) != nullptr);

    GrpcExchange exchange;
    exchange.init();
    exchange.downstream = &downstream;
    exchange.downstream_stream = 1;
    exchange.config_epoch = &cfg;
    exchange.upstream_id = 0;
    exchange.retry_policy = cfg.upstreams[0].grpc_retry;
    exchange.retry_enabled = true;
    exchange.retry_attempts = 1;
    exchange.retry_pending = true;
    exchange.retry_tried_mask = 0x03;
    REQUIRE(exchange.replay_body.init(1024));
    REQUIRE(exchange.replay_body.seal());
    const hpack::Header headers[] = {{{":method", 7}, {"POST", 4}}, {{":path", 5}, {"/svc", 4}}};
    REQUIRE(exchange.replay_headers.capture(headers, 2));
    REQUIRE(exchange.replay_trailers.capture(nullptr, 0));
    REQUIRE(grpc_attach(downstream_h2, &exchange));

    REQUIRE(grpc_bind_retry_attempt(&loop, exchange, now));
    CHECK_EQ(loop.retry_conn.upstream_backend_idx, 2u);
    CHECK_EQ(loop.retry_conn.h2->grpc.connect_attempts, 1u);
    CHECK_EQ(loop.retry_conn.h2->grpc.connect_tried_mask, 0x07u);
    CHECK_EQ(exchange.retry_tried_mask, 0x07u);

    grpc_connected<RetryCloseSelectionFixture>(
        &loop,
        loop.retry_conn,
        {loop.retry_conn.id, -ECONNREFUSED, 0, 0, IoEventType::UpstreamConnect, 0});
    CHECK_EQ(loop.retry_conn.h2->grpc.connect_attempts, 2u);
    CHECK_EQ(loop.retry_conn.upstream_backend_idx, 3u);
    CHECK_EQ(loop.retry_conn.h2->grpc.connect_tried_mask, 0x0fu);
    CHECK_EQ(exchange.retry_tried_mask, 0x07u);

    grpc_connected<RetryCloseSelectionFixture>(
        &loop,
        loop.retry_conn,
        {loop.retry_conn.id, -ECONNREFUSED, 0, 0, IoEventType::UpstreamConnect, 0});
    CHECK_EQ(loop.retry_conn.h2->grpc.connect_attempts, 3u);
    CHECK_EQ(loop.retry_conn.upstream_backend_idx, 4u);
    CHECK_EQ(loop.retry_conn.h2->grpc.connect_tried_mask, 0x1fu);
    CHECK_EQ(exchange.retry_tried_mask, 0x07u);

    grpc_detach(loop.retry_h2, &exchange);
    grpc_detach(downstream_h2, &exchange);
    exchange.upstream = nullptr;
    exchange.replay_body.release();
    loop.grpc_upstreams = nullptr;
    loop.retry_conn.on_close = nullptr;
    if (loop.retry_conn.fd >= 0) close(loop.retry_conn.fd);
    loop.retry_conn.fd = loop.retry_conn.upstream_fd = -1;
    if (loop.retry_conn.recv_slice) loop.pool.free(loop.retry_conn.recv_slice);
}

template <typename Loop>
void grpc_retry_remembers_c5_fallback_before_status_retry_case(rut::test::TestCase* _tc) {
    (void)_tc;
    auto retry_server = std::make_unique<EchoServer>();
    auto success_server = std::make_unique<EchoServer>();
    REQUIRE(retry_server->start());
    REQUIRE(success_server->start());
    retry_server->reply_mode = 1;

    const int reserved = create_listen_socket(0).value_or(-1);
    REQUIRE(reserved >= 0);
    const u16 refused_port = get_port(reserved);
    close(reserved);
    auto shard = std::make_unique<Shard<Loop>>();
    const int lfd = create_listen_socket(0).value_or(-1);
    REQUIRE(lfd >= 0);
    if (!shard->init(0, lfd)) {
        close(lfd);
        SKIP("backend unavailable");
    }
    RouteConfig cfg;
    // Each shard thread starts its independent round-robin cursor at backend 0.
    const u16 ports[3] = {
        refused_port, get_port(retry_server->listen_fd), get_port(success_server->listen_fd)};
    REQUIRE(cfg.add_upstream("grpc", 0x7f000001, ports[0]));
    REQUIRE(cfg.upstreams[0].add_addr(0x7f000001, ports[1]));
    REQUIRE(cfg.upstreams[0].add_addr(0x7f000001, ports[2]));
    cfg.upstreams[0].http2 = true;
    cfg.upstreams[0].grpc_retry = {2, 1024, 1u << 7, 0};
    REQUIRE(cfg.add_proxy("/test.Echo/", 'P', 0));
    shard->route_config = &cfg;
    REQUIRE(shard->spawn(-1));
    {
        Client client;
        CHECK(client.init(get_port(lfd)));
        if (client.fd >= 0) {
            static constexpr u8 request[] = {0, 0, 0, 0, 1, 0x5a};
            CHECK_EQ(client.request_native_raw(0, request, sizeof(request)), 1);
            CHECK(client.until(0, true));
            CHECK(client.rpcs[0].ok);
            CHECK_EQ(retry_server->requests.load(), 1u);
            CHECK_EQ(success_server->requests.load(), 1u);
        }
    }
    shard->stop();
    shard->join();
    CHECK_EQ(shard->shard_metrics.grpc_started, 1u);
    CHECK_EQ(shard->shard_metrics.grpc_active, 0u);
    CHECK_EQ(shard->shard_metrics.grpc_completed[0], 1u);
    shard->loop->force_close_all();
    if (shard->loop->listen_fd >= 0) {
        close(shard->loop->listen_fd);
        shard->loop->listen_fd = -1;
    }
    shard->shutdown();
}

TEST(grpc_proxy, grpc_retry_remembers_c5_fallback_before_status_retry_epoll) {
    grpc_retry_remembers_c5_fallback_before_status_retry_case<EpollEventLoop>(_tc);
}
TEST(grpc_proxy, grpc_retry_remembers_c5_fallback_before_status_retry_iouring) {
    grpc_retry_remembers_c5_fallback_before_status_retry_case<IoUringEventLoop>(_tc);
}

TEST(grpc_proxy, grpc_retry_does_not_replay_after_downstream_response_commit) {
    auto server = std::make_unique<EchoServer>();
    REQUIRE(server->start());
    server->reply_mode = 12;  // Send DATA before the retryable status trailers.
    auto shard = std::make_unique<Shard<EpollEventLoop>>();
    const int lfd = create_listen_socket(0).value_or(-1);
    REQUIRE(lfd >= 0);
    if (!shard->init(0, lfd)) {
        close(lfd);
        SKIP("backend unavailable");
    }
    RouteConfig cfg;
    REQUIRE(cfg.add_upstream("grpc", 0x7f000001, get_port(server->listen_fd)));
    cfg.upstreams[0].http2 = true;
    cfg.upstreams[0].grpc_retry = {3, 1024, 1u << 7, 0};
    REQUIRE(cfg.add_proxy("/test.Echo/", 'P', 0));
    shard->route_config = &cfg;
    REQUIRE(shard->spawn(-1));
    {
        Client client;
        CHECK(client.init(get_port(lfd)));
        if (client.fd >= 0) {
            static constexpr u8 request[] = {0, 0, 0, 0, 1, 0x5a};
            CHECK_EQ(client.request_native_raw(0, request, sizeof(request)), 1);
            CHECK(client.until(0, true));
            CHECK_EQ(client.rpcs[0].status, 7u);
            CHECK_EQ(client.rpcs[0].received, sizeof(request));
            CHECK_EQ(server->requests.load(), 1u);
        }
    }
    shard->stop();
    shard->join();
    CHECK_EQ(shard->shard_metrics.grpc_started, 1u);
    CHECK_EQ(shard->shard_metrics.grpc_active, 0u);
    CHECK_EQ(shard->shard_metrics.grpc_completed[7], 1u);
    CHECK_EQ(shard->shard_metrics.grpc_latency.count, 1u);
    shard->loop->force_close_all();
    if (shard->loop->listen_fd >= 0) {
        close(shard->loop->listen_fd);
        shard->loop->listen_fd = -1;
    }
    shard->shutdown();
}

void grpc_retry_suppressed_deadline_case(rut::test::TestCase* _tc, bool web) {
    auto server = std::make_unique<EchoServer>();
    REQUIRE(server->start());
    server->reply_mode = 1;
    auto shard = std::make_unique<Shard<EpollEventLoop>>();
    const int lfd = create_listen_socket(0).value_or(-1);
    REQUIRE(lfd >= 0);
    if (!shard->init(0, lfd)) {
        close(lfd);
        SKIP("backend unavailable");
    }
    RouteConfig cfg;
    REQUIRE(cfg.add_upstream("grpc", 0x7f000001, get_port(server->listen_fd)));
    cfg.upstreams[0].http2 = true;
    cfg.upstreams[0].grpc_retry = {2, 1024, 1u << 7, 500};
    REQUIRE(cfg.add_proxy("/test.Echo/", 'P', 0));
    shard->route_config = &cfg;
    REQUIRE(shard->spawn(-1));
    {
        Client client;
        CHECK(client.init(get_port(lfd)));
        if (client.fd >= 0) {
            static constexpr u8 request[] = {0, 0, 0, 0, 1, 0x5a};
            const int sid =
                web ? client.request_web(0, request, sizeof(request), false, 2, true, "50m")
                    : client.request_native_raw(0, request, sizeof(request), "50m");
            CHECK_EQ(sid, 1);
            CHECK(client.until(0, true));
            if (!web) {
                CHECK_EQ(client.rpcs[0].status, 4u);
            } else {
                CHECK_GE(client.rpcs[0].response_len, 5u);
                if (client.rpcs[0].response_len >= 5) {
                    GrpcWebTrailer trailers[] = {{{"grpc-status", 11}, {"4", 1}}};
                    u8 expected[64];
                    u32 expected_len = 0;
                    const bool encoded = grpc_web_encode_trailer_envelope(
                        trailers, 1, expected, sizeof(expected), expected_len);
                    CHECK(encoded);
                    if (encoded) {
                        CHECK_EQ(client.rpcs[0].response_len, expected_len);
                        if (client.rpcs[0].response_len == expected_len)
                            CHECK_EQ(memcmp(client.rpcs[0].response.get(), expected, expected_len),
                                     0);
                    }
                }
            }
            CHECK_EQ(server->requests.load(), 1u);
        }
    }
    shard->stop();
    shard->join();
    CHECK_EQ(shard->shard_metrics.grpc_started, 1u);
    CHECK_EQ(shard->shard_metrics.grpc_active, 0u);
    CHECK_EQ(shard->shard_metrics.grpc_completed[4], 1u);
    CHECK_EQ(shard->shard_metrics.grpc_latency.count, 1u);
    shard->loop->force_close_all();
    if (shard->loop->listen_fd >= 0) {
        close(shard->loop->listen_fd);
        shard->loop->listen_fd = -1;
    }
    shard->shutdown();
}
TEST(grpc_proxy, grpc_retry_is_suppressed_when_backoff_exceeds_deadline) {
    grpc_retry_suppressed_deadline_case(_tc, false);
}
TEST(grpc_proxy, grpc_web_retry_is_suppressed_when_backoff_exceeds_deadline) {
    grpc_retry_suppressed_deadline_case(_tc, true);
}

TEST(grpc_proxy, grpc_retry_requires_uncommitted_downstream_response) {
    GrpcExchange exchange;
    exchange.init();
    exchange.retry_enabled = true;
    exchange.retry_policy = {2, 1024, 1u << 7, 0};
    exchange.replay_body.replayable = true;
    exchange.replay_body.sealed = true;
    exchange.replay_headers.valid = true;
    exchange.replay_trailers.valid = true;
    CHECK(grpc_retry_can_schedule(exchange, 7));
    exchange.response_headers_sent = true;
    CHECK_FALSE(grpc_retry_can_schedule(exchange, 7));
    exchange.response_headers_sent = false;
    exchange.response_bytes = 1;
    CHECK_FALSE(grpc_retry_can_schedule(exchange, 7));
}

TEST(grpc_proxy, final_retry_attempt_releases_replay_body_when_end_is_staged) {
    GrpcDriveFixture loop;
    Connection upstream;
    upstream.reset();
    u8 send_storage[SlicePool::kSliceSize]{};
    upstream.send_slice = send_storage;
    upstream.send_buf.bind(send_storage, sizeof(send_storage));
    Http2Conn h2;
    h2.init_client();
    h2.grpc.upstream = true;
    h2.grpc.preface_sent = true;
    h2.peer_settings_seen = true;
    upstream.h2 = &h2;
    REQUIRE(h2.open_stream(1) != nullptr);

    GrpcExchange exchange;
    exchange.init();
    exchange.upstream = &upstream;
    exchange.upstream_stream = 1;
    exchange.request_headers_sent = true;
    exchange.request_end = true;
    exchange.replaying_attempt = true;
    exchange.retry_enabled = true;
    exchange.retry_policy = {2, 1024, 1u << 14, 0};
    exchange.retry_attempts = 2;
    exchange.slot_held = true;
    REQUIRE(exchange.replay_body.init(1024));
    const u8 body[] = {0, 0, 0, 0, 0};
    REQUIRE(exchange.replay_body.append(loop.pool, body, sizeof(body)));
    REQUIRE(exchange.replay_body.seal());
    u8 drained[sizeof(body)];
    CHECK_EQ(exchange.replay_body.copy(drained, sizeof(drained)), sizeof(body));
    const hpack::Header headers[] = {{{":method", 7}, {"POST", 4}}};
    REQUIRE(exchange.replay_headers.capture(headers, 1));
    REQUIRE(exchange.replay_trailers.capture(nullptr, 0));
    REQUIRE(grpc_attach(h2, &exchange));

    grpc_drive_upstream(&loop, upstream);

    CHECK(exchange.request_end_sent);
    CHECK_FALSE(exchange.replaying_attempt);
    CHECK_FALSE(exchange.retry_enabled);
    CHECK_FALSE(exchange.replay_body.replayable);
    CHECK_EQ(exchange.replay_body.storage.head, nullptr);
    CHECK_FALSE(exchange.replay_headers.valid);
    CHECK_FALSE(exchange.replay_trailers.valid);
    CHECK(exchange.slot_held);
    CHECK_FALSE(exchange.response_end);
    CHECK_EQ(h2.grpc.active, 1u);
    CHECK_EQ(loop.pool.bulk_available(), 8u);

    grpc_detach(h2, &exchange);
    grpc_release_slot(&loop, exchange);
}

TEST(grpc_proxy, retry_bind_sync_close_leaves_terminal_completion_to_caller) {
    SyncRetryBindCloseFixture loop;
    ShardMetrics metrics{};
    loop.metrics = &metrics;
    RouteConfig cfg;
    REQUIRE(cfg.add_upstream("grpc", 0x7f000001, 1));
    cfg.upstreams[0].http2 = true;
    cfg.upstreams[0].grpc_retry = {2, 1024, 1u << 14, 0};

    Connection downstream;
    downstream.reset();
    Http2Conn downstream_h2;
    downstream_h2.init_client();
    downstream.h2 = &downstream_h2;
    REQUIRE(downstream_h2.open_stream(1) != nullptr);

    GrpcExchange exchange;
    exchange.init();
    exchange.downstream = &downstream;
    exchange.downstream_stream = 1;
    exchange.config_epoch = &cfg;
    exchange.upstream_id = 0;
    exchange.retry_policy = cfg.upstreams[0].grpc_retry;
    exchange.retry_enabled = true;
    exchange.retry_attempts = 1;
    exchange.retry_pending = true;
    exchange.slot_held = true;
    exchange.observed = true;
    exchange.started_us = monotonic_us();
    REQUIRE(exchange.replay_body.init(1024));
    REQUIRE(exchange.replay_body.seal());
    const hpack::Header headers[] = {{{":method", 7}, {"POST", 4}}, {{":path", 5}, {"/svc", 4}}};
    REQUIRE(exchange.replay_headers.capture(headers, 2));
    REQUIRE(exchange.replay_trailers.capture(nullptr, 0));

    CHECK_FALSE(grpc_bind_retry_attempt(&loop, exchange, monotonic_us()));
    CHECK(loop.closed);
    CHECK_EQ(loop.retry_h2.grpc.active, 0u);
    CHECK_EQ(exchange.upstream, nullptr);
    CHECK_FALSE(exchange.response_end);
    CHECK_EQ(exchange.failure, 0u);
    CHECK(exchange.retry_enabled);
    CHECK(exchange.slot_held);
    CHECK_EQ(loop.released, 0u);
    CHECK_EQ(metrics.grpc_completed[14], 0u);
    // The deadline callback that called bind now owns terminal mutation.
    exchange.retry_pending = false;
    exchange.failure = 14;
    exchange.response_end = true;
    exchange.response_end_sent = true;
    grpc_release_slot(&loop, exchange);
    grpc_observe(&loop, exchange);
    grpc_observe(&loop, exchange);
    CHECK(exchange.response_end);
    CHECK_EQ(exchange.failure, 14u);
    CHECK_FALSE(exchange.slot_held);
    CHECK_EQ(loop.released, 1u);
    CHECK_EQ(metrics.grpc_completed[14], 1u);
}

TEST(grpc_proxy, grpc_tls_identity_failure_does_not_replay_enabled_rpc) {
    GrpcDriveFixture loop;
    Connection upstream;
    upstream.reset();
    Http2Conn h2;
    h2.init_client();
    h2.grpc.upstream = true;
    GrpcExchange exchange;
    exchange.init();
    exchange.upstream = &upstream;
    exchange.retry_enabled = true;
    exchange.retry_policy = {3, 1024, 1u << 14, 0};
    exchange.retry_attempts = 1;
    exchange.replay_body.replayable = true;
    exchange.replay_body.sealed = true;
    exchange.replay_headers.valid = true;
    exchange.replay_trailers.valid = true;
    h2.grpc.streams[0] = &exchange;
    upstream.h2 = &h2;

    // Identity and ALPN failures occur after TCP connect and do not exhaust
    // the TCP connect failover budget (`c5_exhausted` remains false).
    grpc_connection_closed<GrpcDriveFixture>(&loop, upstream);
    CHECK_FALSE(exchange.retry_pending);
    CHECK(exchange.response_end);
    CHECK_EQ(exchange.failure, 14u);
    CHECK_EQ(exchange.retry_attempts, 1u);
}

TEST(grpc_proxy, grpc_retry_cancel_during_backoff_releases_logical_rpc) {
    auto server = std::make_unique<EchoServer>();
    REQUIRE(server->start());
    server->reply_mode = 1;
    auto shard = std::make_unique<Shard<EpollEventLoop>>();
    const int lfd = create_listen_socket(0).value_or(-1);
    REQUIRE(lfd >= 0);
    if (!shard->init(0, lfd)) {
        close(lfd);
        SKIP("backend unavailable");
    }
    RouteConfig cfg;
    REQUIRE(cfg.add_upstream("grpc", 0x7f000001, get_port(server->listen_fd)));
    cfg.upstreams[0].http2 = true;
    cfg.upstreams[0].grpc_retry = {2, 1024, 1u << 7, 250};
    REQUIRE(cfg.add_proxy("/test.Echo/", 'P', 0));
    shard->route_config = &cfg;
    REQUIRE(shard->spawn(-1));
    {
        Client client;
        CHECK(client.init(get_port(lfd)));
        if (client.fd >= 0) {
            static constexpr u8 request[] = {0, 0, 0, 0, 1, 0x5a};
            CHECK_EQ(client.request_native_raw(0, request, sizeof(request)), 1);
            const u64 first_attempt_deadline = monotonic_us() + 1000000;
            while (!server->requests.load() && monotonic_us() < first_attempt_deadline)
                CHECK(client.step());
            CHECK_EQ(server->requests.load(), 1u);
            usleep(50000);  // Allow the trailers-only failure to enter backoff.
            CHECK_EQ(
                nghttp2_submit_rst_stream(client.session, NGHTTP2_FLAG_NONE, 1, NGHTTP2_CANCEL), 0);
            CHECK(flush_session(client.session, client.fd, client.ssl));
            usleep(350000);
            CHECK_EQ(server->requests.load(), 1u);
            CHECK_EQ(client.request_native_raw(1, request, sizeof(request)), 3);
            CHECK(client.until(1, true));
            CHECK(client.rpcs[1].ok);
            CHECK_EQ(server->requests.load(), 2u);
        }
    }
    shard->stop();
    shard->join();
    CHECK_EQ(shard->shard_metrics.grpc_started, 2u);
    CHECK_EQ(shard->shard_metrics.grpc_active, 0u);
    CHECK_EQ(shard->shard_metrics.grpc_completed[0], 1u);
    CHECK_EQ(shard->shard_metrics.grpc_latency.count, 2u);
    shard->loop->force_close_all();
    if (shard->loop->listen_fd >= 0) {
        close(shard->loop->listen_fd);
        shard->loop->listen_fd = -1;
    }
    shard->shutdown();
}

TEST(grpc_proxy, grpc_retry_uses_admission_config_after_reload) {
    auto original_server = std::make_unique<EchoServer>();
    auto reloaded_server = std::make_unique<EchoServer>();
    REQUIRE(original_server->start());
    REQUIRE(reloaded_server->start());
    original_server->reply_mode = 1;
    auto shard = std::make_unique<Shard<EpollEventLoop>>();
    const int lfd = create_listen_socket(0).value_or(-1);
    REQUIRE(lfd >= 0);
    if (!shard->init(0, lfd)) {
        close(lfd);
        SKIP("backend unavailable");
    }
    RouteConfig original_cfg;
    REQUIRE(original_cfg.add_upstream("grpc", 0x7f000001, get_port(original_server->listen_fd)));
    original_cfg.upstreams[0].http2 = true;
    original_cfg.upstreams[0].grpc_retry = {2, 1024, 1u << 7, 250};
    REQUIRE(original_cfg.add_proxy("/test.Echo/", 'P', 0));
    RouteConfig reloaded_cfg;
    REQUIRE(reloaded_cfg.add_upstream("grpc", 0x7f000001, get_port(reloaded_server->listen_fd)));
    reloaded_cfg.upstreams[0].http2 = true;
    reloaded_cfg.upstreams[0].grpc_retry = {2, 1024, 1u << 7, 250};
    REQUIRE(reloaded_cfg.add_proxy("/test.Echo/", 'P', 0));
    shard->route_config = &original_cfg;
    REQUIRE(shard->spawn(-1));
    {
        Client client;
        CHECK(client.init(get_port(lfd)));
        if (client.fd >= 0) {
            static constexpr u8 request[] = {0, 0, 0, 0, 1, 0x5a};
            CHECK_EQ(client.request_native_raw(0, request, sizeof(request)), 1);
            const u64 first_attempt_deadline = monotonic_us() + 1000000;
            while (!original_server->requests.load() && monotonic_us() < first_attempt_deadline)
                CHECK(client.step());
            CHECK_EQ(original_server->requests.load(), 1u);
            CHECK(shard->reload_config(&reloaded_cfg, 1));
            CHECK(client.until(0, true));
            CHECK(client.rpcs[0].ok);
            CHECK_EQ(original_server->requests.load(), 2u);
            CHECK_EQ(reloaded_server->requests.load(), 0u);
            CHECK_EQ(client.request_native_raw(1, request, sizeof(request)), 3);
            CHECK(client.until(1, true));
            CHECK(client.rpcs[1].ok);
            CHECK_EQ(reloaded_server->requests.load(), 1u);
        }
    }
    shard->stop();
    shard->join();
    CHECK_EQ(shard->shard_metrics.grpc_started, 2u);
    CHECK_EQ(shard->shard_metrics.grpc_active, 0u);
    CHECK_EQ(shard->shard_metrics.grpc_completed[0], 2u);
    CHECK_EQ(shard->shard_metrics.grpc_latency.count, 2u);
    shard->loop->force_close_all();
    if (shard->loop->listen_fd >= 0) {
        close(shard->loop->listen_fd);
        shard->loop->listen_fd = -1;
    }
    shard->shutdown();
}

template <typename Loop>
void grpc_retry_recovers_after_single_endpoint_connect_refusal(rut::test::TestCase* _tc) {
    (void)_tc;
    auto server = std::make_unique<EchoServer>();
    const int reserved = create_listen_socket(0).value_or(-1);
    REQUIRE(reserved >= 0);
    const u16 backend_port = get_port(reserved);
    close(reserved);

    auto shard = std::make_unique<Shard<Loop>>();
    const int lfd = create_listen_socket(0).value_or(-1);
    REQUIRE(lfd >= 0);
    if (!shard->init(0, lfd)) {
        close(lfd);
        SKIP("backend unavailable");
    }
    RouteConfig cfg;
    REQUIRE(cfg.add_upstream("grpc", 0x7f000001, backend_port));
    cfg.upstreams[0].http2 = true;
    cfg.upstreams[0].grpc_retry = {2, 1024, 1u << 14, 500};
    REQUIRE(cfg.add_proxy("/test.Echo/", 'P', 0));
    shard->route_config = &cfg;
    REQUIRE(shard->spawn(-1));
    {
        Client client;
        CHECK(client.init(get_port(lfd)));
        if (client.fd >= 0) {
            static constexpr u8 request[] = {0, 0, 0, 0, 1, 0x5a};
            CHECK_EQ(client.request_native_raw(0, request, sizeof(request)), 1);
            CHECK(client.step());  // Flush admission and start the first connection attempt.
            // Let the one-address C5 connect sequence exhaust before opening
            // the listener; the logical call should remain pending in backoff.
            usleep(100000);
            CHECK_EQ(server->requests.load(), 0u);
            CHECK_EQ(shard->shard_metrics.grpc_started, 1u);
            CHECK_EQ(shard->shard_metrics.grpc_active, 1u);
            CHECK_FALSE(client.rpcs[0].response_end);
            CHECK(server->start(false, false, true, backend_port));
            CHECK(client.until(0, true));
            CHECK(client.rpcs[0].ok);
            CHECK_EQ(server->requests.load(), 1u);
            CHECK_EQ(server->accepts.load(), 1u);
        }
    }
    shard->stop();
    shard->join();
    CHECK_EQ(shard->shard_metrics.grpc_started, 1u);
    CHECK_EQ(shard->shard_metrics.grpc_active, 0u);
    CHECK_EQ(shard->shard_metrics.grpc_completed[0], 1u);
    CHECK_EQ(shard->shard_metrics.grpc_latency.count, 1u);
    shard->loop->force_close_all();
    if (shard->loop->listen_fd >= 0) {
        close(shard->loop->listen_fd);
        shard->loop->listen_fd = -1;
    }
    shard->shutdown();
}

TEST(grpc_proxy, grpc_retry_c5_single_endpoint_recovers_epoll) {
    grpc_retry_recovers_after_single_endpoint_connect_refusal<EpollEventLoop>(_tc);
}
TEST(grpc_proxy, grpc_retry_c5_single_endpoint_recovers_iouring) {
    grpc_retry_recovers_after_single_endpoint_connect_refusal<IoUringEventLoop>(_tc);
}

TEST(grpc_proxy, streaming_and_pooling_epoll) {
    streaming_case<EpollEventLoop>(_tc);
}
TEST(grpc_proxy, streaming_and_pooling_iouring) {
    streaming_case<IoUringEventLoop>(_tc);
}
TEST(grpc_proxy, first_large_streaming_rpc_epoll) {
    streaming_case<EpollEventLoop>(_tc, false, false, false, true);
}
TEST(grpc_proxy, first_large_streaming_rpc_iouring) {
    streaming_case<IoUringEventLoop>(_tc, false, false, false, true);
}
template <typename Loop>
void grpc_connect_failover_case(rut::test::TestCase* _tc, bool tls, bool timeout_first = false) {
    (void)_tc;
    GrpcBackendHealthReset health_reset{};
    Loop loop;
    if (!loop.init(0, -1).has_value()) SKIP("event backend unavailable");
    RouteConfig cfg;
    int reserved[4];
    u16 ports[4];
    for (u32 i = 0; i < 4; i++) {
        reserved[i] = create_listen_socket(0).value_or(-1);
        REQUIRE(reserved[i] >= 0);
        ports[i] = get_port(reserved[i]);
        close(reserved[i]);
    }
    REQUIRE(cfg.add_upstream("grpc", 0x7f000001, ports[0]).has_value());
    for (u32 i = 1; i < 4; i++) REQUIRE(cfg.upstreams[0].add_addr(0x7f000001, ports[i]));
    cfg.upstreams[0].tls.enabled = tls;
    const RouteConfig* cfg_ptr = &cfg;
    loop.config_ptr = &cfg_ptr;

    Connection* conn = loop.alloc_conn();
    REQUIRE(conn != nullptr);
    REQUIRE(loop.alloc_h2(*conn));
    conn->h2->init_client();
    GrpcExchange exchange;
    exchange.init();
    exchange.upstream = conn;
    exchange.upstream_id = 0;
    conn->request_config = &cfg;
    conn->upstream_idx = 0;
    conn->upstream_backend_idx = static_cast<u8>(select_backend(0, 4, monotonic_us()));
    conn->h2->grpc.upstream = true;
    conn->h2->grpc.connecting = true;
    conn->h2->grpc.connected_at_us = 123;
    conn->h2->grpc.connect_attempts = 1;
    conn->h2->grpc.connect_tried_mask = static_cast<u8>(1u << conn->upstream_backend_idx);
    conn->h2->grpc.streams[0] = &exchange;
    conn->h2->grpc.active = 1;
    conn->fd = conn->upstream_fd = UpstreamPool::create_socket();
    REQUIRE(conn->fd >= 0);
    conn->on_close = &grpc_connection_closed<Loop>;
    conn->set_slots(nullptr, nullptr, nullptr, &grpc_connected<Loop>);
    REQUIRE(loop.submit_connect(*conn,
                                &cfg.upstreams[0].addrs[conn->upstream_backend_idx],
                                sizeof(cfg.upstreams[0].addrs[0])));

    u32 failed_attempts = 1;
    bool timeout_successor_observed = false;
    const u8 timed_out_backend = conn->upstream_backend_idx;
    const u32 timed_out_episode = conn->upstream_episode;
    // Force the first pending connect past its timeout without sleeping. This
    // exercises timeout failover before its normal completion event is handled.
    if (timeout_first) {
        conn->h2->grpc.connected_at_us =
            monotonic_us() - static_cast<u64>(loop.upstream_timeout) * 1000000 - 1;
        grpc_tick(&loop, *conn);
        if (!conn->h2->grpc.connect_retry_pending) {
            CHECK_EQ(conn->h2->grpc.connect_attempts, 2u);
            CHECK_EQ(__builtin_popcount(conn->h2->grpc.connect_tried_mask), 2);
            CHECK_GT(conn->h2->grpc.connected_at_us, 123u);
            CHECK(conn->h2->grpc.connecting);
            CHECK_EQ(conn->h2->grpc.streams[0], &exchange);
            CHECK(exchange.upstream == conn);
            REQUIRE(backend_health(0, timed_out_backend) != nullptr);
            CHECK_EQ(backend_health(0, timed_out_backend)->fails, 1u);
            failed_attempts = conn->h2->grpc.connect_attempts;
        }
    }

    IoEvent events[16];
    for (u32 wait = 0; wait < 16 && conn->h2; wait++) {
        const u8 previous_mask = conn->h2->grpc.connect_tried_mask;
        const u32 count = loop.backend.wait(events, 16, loop.conns, loop.connection_capacity);
        REQUIRE(count != 0);
        loop.dispatch_batch(events, count);
        if (!conn->h2) break;
        if (conn->h2->grpc.connect_retry_pending) {
            grpc_tick(&loop, *conn);
            if (!conn->h2->grpc.connect_retry_pending) {
                CHECK_EQ(conn->h2->grpc.connect_attempts, 2u);
                CHECK_EQ(__builtin_popcount(conn->h2->grpc.connect_tried_mask), 2);
                CHECK_GT(conn->h2->grpc.connected_at_us, 123u);
                CHECK(conn->h2->grpc.connecting);
                CHECK_EQ(conn->h2->grpc.streams[0], &exchange);
                CHECK(exchange.upstream == conn);
                REQUIRE(backend_health(0, timed_out_backend) != nullptr);
                CHECK_EQ(backend_health(0, timed_out_backend)->fails, 1u);
                failed_attempts = conn->h2->grpc.connect_attempts;
                timeout_successor_observed = true;
                if constexpr (std::is_same_v<Loop, IoUringEventLoop>) {
                    const i32 successor_fd = conn->upstream_fd;
                    const u32 successor_episode = conn->upstream_episode;
                    const u32 successor_pending = conn->pending_ops;
                    const u8 successor_mask = conn->h2->grpc.connect_tried_mask;
                    loop.dispatch({conn->id,
                                   -ECANCELED,
                                   0,
                                   0,
                                   IoEventType::UpstreamConnect,
                                   0,
                                   0,
                                   timed_out_episode});
                    CHECK_EQ(conn->upstream_fd, successor_fd);
                    CHECK_EQ(conn->upstream_episode, successor_episode);
                    CHECK_EQ(conn->pending_ops, successor_pending);
                    CHECK(conn->upstream_connect_armed);
                    CHECK_EQ(conn->h2->grpc.connect_attempts, 2u);
                    CHECK_EQ(conn->h2->grpc.connect_tried_mask, successor_mask);
                    break;
                }
            }
            continue;
        }
        if (conn->h2->grpc.connect_attempts == failed_attempts) continue;
        CHECK_EQ(conn->h2->grpc.connect_attempts, failed_attempts + 1);
        CHECK_NE(conn->h2->grpc.connect_tried_mask, previous_mask);
        CHECK_EQ(__builtin_popcount(conn->h2->grpc.connect_tried_mask), failed_attempts + 1);
        CHECK_GT(conn->h2->grpc.connected_at_us, 123u);
        CHECK(conn->h2->grpc.connecting);
        CHECK_EQ(conn->h2->grpc.streams[0], &exchange);
        CHECK_EQ(conn->h2->grpc.active, 1u);
        CHECK(exchange.upstream == conn);
        CHECK_FALSE(exchange.response_end);
        failed_attempts++;
    }
    if constexpr (std::is_same_v<Loop, IoUringEventLoop>) {
        if (timeout_first && timeout_successor_observed && conn->h2) {
            CHECK_EQ(conn->h2->grpc.connect_attempts, 2u);
            CHECK(conn->upstream_connect_armed);
            CHECK_EQ(conn->pending_ops, 1u);
            CHECK_EQ(conn->h2->grpc.streams[0], &exchange);
            loop.close_conn(*conn);
            loop.shutdown();
            return;
        }
    }
    if (timeout_first && conn->h2) {
        CHECK_EQ(conn->pending_ops, 0u);
        CHECK_EQ(conn->upstream_retirement_target_owned, 0u);
        CHECK_EQ(conn->upstream_retirement_cancel_owned, 0u);
        CHECK_EQ(conn->upstream_retirement_cancel_retry, 0u);
        CHECK_FALSE(conn->upstream_retirement_active);
        CHECK_FALSE(conn->upstream_connect_armed);
        CHECK_EQ(conn->h2->grpc.connect_retry_pending, false);
        CHECK_EQ(conn->h2->grpc.connect_attempts, 3u);
    }
    CHECK_EQ(failed_attempts, 3u);
    CHECK(conn->h2 == nullptr);
    CHECK(exchange.upstream == nullptr);
    CHECK(exchange.response_end);
    CHECK_EQ(exchange.failure, 14u);
    if (timeout_first) CHECK_EQ(backend_health(0, timed_out_backend)->fails, 1u);
    loop.shutdown();
}
TEST(grpc_proxy, connect_failover_epoll) {
    grpc_connect_failover_case<EpollEventLoop>(_tc, false);
}
TEST(grpc_proxy, connect_failover_iouring) {
    grpc_connect_failover_case<IoUringEventLoop>(_tc, false);
}
TEST(grpc_proxy, tls_connect_failover_before_handshake_epoll) {
    grpc_connect_failover_case<EpollEventLoop>(_tc, true);
}
TEST(grpc_proxy, tls_connect_failover_before_handshake_iouring) {
    grpc_connect_failover_case<IoUringEventLoop>(_tc, true);
}
TEST(grpc_proxy, connect_timeout_failover_epoll) {
    grpc_connect_failover_case<EpollEventLoop>(_tc, false, true);
}
TEST(grpc_proxy, connect_timeout_failover_iouring) {
    grpc_connect_failover_case<IoUringEventLoop>(_tc, false, true);
}

TEST(grpc_proxy, connect_timeout_retry_waits_for_both_retirement_owners) {
    for (bool cancel_first : {false, true}) {
        GrpcBackendHealthReset health_reset{};
        GrpcConnectRetirementFixture loop;
        RouteConfig cfg;
        REQUIRE(cfg.add_upstream("grpc", 0x7f000001, 12345).has_value());
        REQUIRE(cfg.upstreams[0].add_addr(0x7f000001, 12346));
        const RouteConfig* cfg_ptr = &cfg;
        loop.config_ptr = &cfg_ptr;

        Connection conn;
        conn.reset();
        Http2Conn h2;
        h2.init_client();
        conn.h2 = &h2;
        conn.request_config = &cfg;
        conn.upstream_idx = 0;
        conn.upstream_backend_idx = 0;
        conn.fd = conn.upstream_fd = UpstreamPool::create_socket();
        REQUIRE(conn.fd >= 0);
        conn.pending_ops = 1;
        conn.upstream_connect_armed = true;
        GrpcExchange exchange;
        exchange.init();
        exchange.upstream = &conn;
        h2.grpc.upstream = true;
        h2.grpc.connecting = true;
        h2.grpc.active = 1;
        h2.grpc.connected_at_us = monotonic_us() - 2000000;
        h2.grpc.connect_attempts = 1;
        h2.grpc.connect_tried_mask = 1;
        h2.grpc.streams[0] = &exchange;

        grpc_tick(&loop, conn);
        CHECK(h2.grpc.connect_retry_pending);
        CHECK_EQ(conn.upstream_retirement_target_owned, kUpstreamOpConnect);
        CHECK_EQ(conn.upstream_retirement_cancel_owned, kUpstreamOpConnect);
        CHECK_EQ(loop.connect_submissions, 0u);
        const u32 old_episode = conn.upstream_retiring_episode;
        auto retire_target = [&]() {
            conn.upstream_retirement_target_owned = 0;
            conn.pending_ops--;
            conn.upstream_retirement_active = conn.upstream_retirement_cancel_owned != 0 ||
                                              conn.upstream_retirement_cancel_retry != 0;
        };
        auto retire_cancel = [&]() {
            conn.upstream_retirement_cancel_owned = 0;
            conn.pending_ops--;
            conn.upstream_retirement_active = conn.upstream_retirement_target_owned != 0 ||
                                              conn.upstream_retirement_cancel_retry != 0;
        };
        if (cancel_first)
            retire_cancel();
        else
            retire_target();
        grpc_tick(&loop, conn);
        CHECK_EQ(loop.connect_submissions, 0u);
        CHECK(h2.grpc.connect_retry_pending);
        if (cancel_first)
            retire_target();
        else
            retire_cancel();
        grpc_tick(&loop, conn);
        CHECK_FALSE(h2.grpc.connect_retry_pending);
        CHECK_EQ(loop.connect_submissions, 1u);
        CHECK_EQ(h2.grpc.connect_attempts, 2u);
        CHECK_EQ(conn.upstream_episode, old_episode + 1u);
        CHECK(conn.upstream_connect_armed);
        CHECK_EQ(conn.pending_ops, 1u);
        CHECK_EQ(h2.grpc.streams[0], &exchange);
        CHECK_EQ(backend_health(0, 0)->fails, 1u);

        loop.close_released_upstream(conn);
        conn.fd = -1;
    }
}

TEST(grpc_proxy, connect_timeout_retry_expires_rpc_before_retirement_finishes) {
    GrpcBackendHealthReset health_reset{};
    GrpcConnectRetirementFixture loop;
    RouteConfig cfg;
    REQUIRE(cfg.add_upstream("grpc", 0x7f000001, 12345).has_value());
    REQUIRE(cfg.upstreams[0].add_addr(0x7f000001, 12346));
    const RouteConfig* cfg_ptr = &cfg;
    loop.config_ptr = &cfg_ptr;

    Connection conn;
    conn.reset();
    Http2Conn h2;
    h2.init_client();
    conn.h2 = &h2;
    conn.request_config = &cfg;
    conn.upstream_idx = 0;
    conn.upstream_backend_idx = 0;
    conn.fd = conn.upstream_fd = UpstreamPool::create_socket();
    REQUIRE(conn.fd >= 0);
    conn.pending_ops = 1;
    conn.upstream_connect_armed = true;
    Connection downstream;
    downstream.reset();
    Http2Conn downstream_h2;
    downstream_h2.init_client();
    downstream.h2 = &downstream_h2;
    GrpcExchange exchange;
    exchange.init();
    exchange.upstream = &conn;
    exchange.downstream = &downstream;
    exchange.deadline_us = monotonic_us() + 1000000;
    h2.grpc.upstream = true;
    h2.grpc.connecting = true;
    h2.grpc.connected_at_us = monotonic_us() - 2000000;
    h2.grpc.connect_attempts = 1;
    h2.grpc.connect_tried_mask = 1;
    REQUIRE(grpc_attach(h2, &exchange));
    REQUIRE(grpc_attach(downstream_h2, &exchange));

    grpc_tick(&loop, conn);
    REQUIRE(h2.grpc.connect_retry_pending);
    // The downstream RPC deadline elapses while the old connect and cancel
    // still own the socket slot.
    exchange.deadline_us = monotonic_us() - 1;
    grpc_tick(&loop, conn);
    CHECK(loop.closed);
    CHECK_EQ(loop.connect_submissions, 0u);
    CHECK_EQ(exchange.failure, 4u);
    CHECK_EQ(h2.grpc.active, 0u);
    CHECK(exchange.upstream == nullptr);
    loop.close_released_upstream(conn);
}

TEST(grpc_proxy, connect_timeout_exhaustion_records_backend_once) {
    GrpcBackendHealthReset health_reset{};
    GrpcConnectRetirementFixture loop;
    RouteConfig cfg;
    REQUIRE(cfg.add_upstream("grpc", 0x7f000001, 12345).has_value());
    REQUIRE(cfg.upstreams[0].add_addr(0x7f000001, 12346));
    REQUIRE(cfg.upstreams[0].add_addr(0x7f000001, 12347));
    const RouteConfig* cfg_ptr = &cfg;
    loop.config_ptr = &cfg_ptr;

    Connection conn;
    conn.reset();
    Http2Conn h2;
    h2.init_client();
    conn.h2 = &h2;
    conn.request_config = &cfg;
    conn.upstream_idx = 0;
    conn.upstream_backend_idx = 0;
    conn.fd = conn.upstream_fd = UpstreamPool::create_socket();
    REQUIRE(conn.fd >= 0);
    conn.pending_ops = 1;
    conn.upstream_connect_armed = true;
    GrpcExchange exchange;
    exchange.init();
    exchange.upstream = &conn;
    h2.grpc.upstream = true;
    h2.grpc.connecting = true;
    h2.grpc.active = 1;
    h2.grpc.connected_at_us = monotonic_us() - 2000000;
    h2.grpc.connect_attempts = 3;
    h2.grpc.connect_tried_mask = 7;
    h2.grpc.streams[0] = &exchange;

    grpc_tick(&loop, conn);
    REQUIRE(h2.grpc.connect_retry_pending);
    CHECK_EQ(backend_health(0, 0)->fails, 1u);
    conn.upstream_retirement_target_owned = 0;
    conn.upstream_retirement_cancel_owned = 0;
    conn.upstream_retirement_active = false;
    conn.pending_ops = 0;
    grpc_tick(&loop, conn);
    CHECK(loop.closed);
    CHECK(h2.grpc.c5_exhausted);
    CHECK_EQ(loop.connect_submissions, 0u);
    CHECK_EQ(backend_health(0, 0)->fails, 1u);
    loop.close_released_upstream(conn);
    conn.fd = -1;
}

template <typename Loop>
void grpc_connect_failover_success_case(rut::test::TestCase* _tc) {
    (void)_tc;
    GrpcBackendHealthReset health_reset{};
    auto server = std::make_unique<EchoServer>();
    REQUIRE(server->start());
    auto shard = std::make_unique<Shard<Loop>>();
    const int lfd = create_listen_socket(0).value_or(-1);
    REQUIRE(lfd >= 0);
    if (!shard->init(0, lfd).has_value()) {
        close(lfd);
        SKIP("backend unavailable");
    }
    REQUIRE(shard->init_access_log().has_value());

    // The shard thread has its own round-robin cursor, initialized to zero.
    // Keep backend 0 closed and backend 1 live so its first attempt reliably
    // fails and the retry reaches the echo server.
    const int refused_fd = create_listen_socket(0).value_or(-1);
    REQUIRE(refused_fd >= 0);
    const u16 refused_port = get_port(refused_fd);
    close(refused_fd);

    RouteConfig cfg;
    const u16 ports[2] = {refused_port, get_port(server->listen_fd)};
    REQUIRE(cfg.add_upstream("grpc", 0x7f000001, ports[0]).has_value());
    REQUIRE(cfg.upstreams[0].add_addr(0x7f000001, ports[1]));
    cfg.upstreams[0].http2 = true;
    REQUIRE(cfg.add_proxy("/test.Echo/", 'P', 0));
    shard->route_config = &cfg;
    const bool spawned = shard->spawn(-1).has_value();
    CHECK(spawned);
    if (spawned) {
        Client client;
        CHECK(client.init(get_port(lfd), false));
        if (client.fd >= 0) {
            CHECK_EQ(client.request(0, 128, true), 1);
            CHECK(client.until(0, true));
            CHECK(client.rpcs[0].ok && client.rpcs[0].trailer);
            CHECK_EQ(client.rpcs[0].received, 128u);
        }
    }
    shard->stop();
    shard->join();
    if (spawned) {
        CHECK_EQ(server->requests.load(), 1u);
        CHECK_EQ(server->accepts.load(), 1u);
        CHECK_EQ(shard->shard_metrics.grpc_started, 1u);
        CHECK_EQ(shard->shard_metrics.grpc_active, 0u);
        CHECK_EQ(shard->shard_metrics.grpc_completed[0], 1u);
        CHECK_EQ(shard->shard_metrics.grpc_latency.count, 1u);
        auto* upstream = shard->loop->grpc_upstreams;
        CHECK(upstream != nullptr);
        if (upstream != nullptr) {
            CHECK(upstream->h2 != nullptr);
        }
        if (upstream != nullptr && upstream->h2 != nullptr) {
            CHECK_EQ(upstream->h2->grpc.connect_attempts, 2u);
            CHECK_EQ(upstream->h2->grpc.connect_tried_mask, 3u);
            CHECK_EQ(upstream->upstream_backend_idx, 1u);
        }
    }
    shard->shutdown();
}

TEST(grpc_proxy, connect_failover_success_epoll) {
    grpc_connect_failover_success_case<EpollEventLoop>(_tc);
}
TEST(grpc_proxy, connect_failover_success_iouring) {
    grpc_connect_failover_success_case<IoUringEventLoop>(_tc);
}

TEST(grpc_proxy, failed_connect_ejects_selected_backend) {
    GrpcBackendHealthReset health_reset{};
    auto loop = std::make_unique<EventLoop<MockBackend>>();
    REQUIRE(loop->init(0, -1).has_value());
    auto* health = backend_health(0, 0);
    REQUIRE(health != nullptr);
    const u64 now = monotonic_us();
    for (u32 i = 0; i < kBackendFailThreshold; i++) {
        Connection* conn = loop->alloc_conn();
        REQUIRE(conn != nullptr);
        conn->upstream_idx = 0;
        conn->upstream_backend_idx = 0;
        grpc_connected<EventLoop<MockBackend>>(
            loop.get(), *conn, {conn->id, -ECONNREFUSED, 0, 0, IoEventType::UpstreamConnect, 0});
    }
    CHECK_EQ(health->fails, kBackendFailThreshold);
    CHECK_EQ(select_backend(0, 2, now + 3), 1u);
    loop->shutdown();
}
TEST(grpc_proxy, successful_rpc_clears_consecutive_failures) {
    GrpcBackendHealthReset health_reset{};
    auto loop = std::make_unique<EpollEventLoop>();
    REQUIRE(loop->init(0, -1).has_value());
    auto* health = backend_health(0, 0);
    REQUIRE(health != nullptr);
    for (u32 i = 0; i < 2; i++) {
        Connection* conn = loop->alloc_conn();
        REQUIRE(conn != nullptr);
        conn->upstream_idx = 0;
        conn->upstream_backend_idx = 0;
        grpc_connected<EpollEventLoop>(
            loop.get(), *conn, {conn->id, -ECONNREFUSED, 0, 0, IoEventType::UpstreamConnect, 0});
    }
    CHECK_EQ(health->fails, 2u);
    Connection* connected = loop->alloc_conn();
    REQUIRE(connected != nullptr);
    connected->upstream_idx = 0;
    connected->upstream_backend_idx = 0;
    REQUIRE(loop->alloc_h2(*connected));
    connected->h2->grpc.connecting = true;
    connected->h2->peer_settings_seen = true;
    grpc_record_handshake_result(*connected, true, monotonic_us());
    grpc_connected<EpollEventLoop>(
        loop.get(), *connected, {connected->id, 1, 0, 0, IoEventType::UpstreamConnect, 0});
    CHECK_EQ(health->fails, 2u);
    Connection* final_attempt = loop->alloc_conn();
    REQUIRE(final_attempt != nullptr);
    final_attempt->upstream_idx = 0;
    final_attempt->upstream_backend_idx = 0;
    grpc_connected<EpollEventLoop>(
        loop.get(),
        *final_attempt,
        {final_attempt->id, -ECONNREFUSED, 0, 0, IoEventType::UpstreamConnect, 0});
    CHECK_EQ(health->fails, 3u);
    loop->shutdown();
}
TEST(grpc_proxy, deferred_cancel_flushes_after_full_control_buffer) {
    Http2Conn h{};
    h.grpc.init();
    h.grpc.control_len = sizeof(h.grpc.control) - 6;
    grpc_queue_cancel(h, 17);
    CHECK_EQ(h.grpc.pending_cancel_count, 1u);
    CHECK_EQ(h.grpc.control_len, sizeof(h.grpc.control) - 6);
    grpc_queue_cancel(h, 17);
    CHECK_EQ(h.grpc.pending_cancel_count, 1u);
    h.grpc.control_len = 0;
    grpc_flush_pending_cancels(h);
    CHECK_EQ(h.grpc.pending_cancel_count, 0u);
    CHECK_EQ(h.grpc.control_len, 13u);
    CHECK_EQ(h.grpc.control[3], 0x3u);
    CHECK_EQ(h.grpc.control[8], 17u);
    CHECK_EQ(h.grpc.control[12], static_cast<u8>(Http2Error::Cancel));
    h.grpc.init();
    CHECK_EQ(h.grpc.pending_cancel_count, 0u);
}
TEST(grpc_proxy, request_header_filter_preserves_only_trailers_te) {
    const hpack::Header allowed[] = {{Str{"te", 2}, Str{"trailers", 8}},
                                     {Str{"x-meta", 6}, Str{"value", 5}}};
    const hpack::Header blocked[] = {{Str{"connection", 10}, Str{"close", 5}},
                                     {Str{"keep-alive", 10}, Str{"timeout=5", 8}},
                                     {Str{"proxy-connection", 16}, Str{"keep-alive", 10}},
                                     {Str{"transfer-encoding", 17}, Str{"chunked", 7}},
                                     {Str{"upgrade", 7}, Str{"h2c", 3}},
                                     {Str{"te", 2}, Str{"gzip", 4}}};
    for (const auto& h : allowed) CHECK(grpc_request_header_allowed(h));
    for (const auto& h : blocked) CHECK(!grpc_request_header_allowed(h));
}
TEST(grpc_proxy, content_type_prefix_is_ascii_case_insensitive) {
    CHECK(grpc_content_type({"Application/GRPC", 16}));
    CHECK(grpc_content_type({"APPLICATION/grpc+proto", 22}));
    CHECK(grpc_content_type({"application/grpc; charset=utf-8", 32}));
    CHECK(!grpc_content_type({"application/grpcx", 17}));
}
TEST(grpc_proxy, request_classifier_accepts_web_modes_for_body_dispatch) {
    ParsedRequest req{};
    req.headers[0] = {lit_str("content-type"), lit_str("application/grpc-web")};
    req.header_count = 1;
    CHECK(grpc_request(req));
    CHECK_EQ(grpc_request_mode(req), GrpcWebContentType::Binary);
    req.headers[0].value = lit_str("application/grpc-web-text+proto");
    CHECK(grpc_request(req));
    CHECK_EQ(grpc_request_mode(req), GrpcWebContentType::Text);
    req.headers[0].value = lit_str("application/grpcx");
    CHECK(!grpc_request(req));
}
TEST(grpc_proxy, grpc_web_accept_selects_response_mode_independently) {
    auto mode_for = [](GrpcWebContentType request_mode, const hpack::Header* headers, u32 count) {
        return grpc_web_response_mode(headers, count, request_mode);
    };
    const hpack::Header text_accept[] = {
        {lit_str("accept"), lit_str("Application/Grpc-Web-Text+proto; q=1.000")}};
    const hpack::Header binary_accept[] = {
        {lit_str("accept"),
         lit_str("application/grpc-web; q=0.8, application/grpc-web-text;q=0.2")}};
    const hpack::Header wildcard_exclusion[] = {
        {lit_str("accept"), lit_str("application/grpc-web-text;q=0, */*;q=1")}};
    const hpack::Header text_over_binary_wildcard[] = {
        {lit_str("accept"), lit_str("application/grpc-web-text;q=1, */*;q=1")}};
    const hpack::Header binary_over_text_wildcard[] = {
        {lit_str("accept"), lit_str("application/grpc-web;q=1, application/*;q=1")}};
    const hpack::Header duplicate_q[] = {
        {lit_str("accept"), lit_str("application/grpc-web-text;q=1;q=0")}};
    const hpack::Header multiple_physical[] = {
        {lit_str("accept"), lit_str("application/grpc-web-text;q=0.4")},
        {lit_str("accept"), lit_str("application/grpc-web;q=0.9")}};
    const hpack::Header ows[] = {
        {lit_str("accept"), lit_str(" \t application/grpc-web-text \t; q = 0.7 \t")}};
    const hpack::Header both_zero[] = {
        {lit_str("accept"), lit_str("application/grpc-web;q=0, application/grpc-web-text;q=0")}};
    const hpack::Header unknown_only[] = {
        {lit_str("accept"), lit_str("application/json, text/plain;q=0.5")}};
    const hpack::Header same_q_tie[] = {
        {lit_str("accept"),
         lit_str("application/grpc-web;q=0.7, application/grpc-web-text;q=0.7")}};
    const hpack::Header bad_q_values[][1] = {
        {{lit_str("accept"), lit_str("application/grpc-web-text;q=")}},
        {{lit_str("accept"), lit_str("application/grpc-web-text;q=2")}},
        {{lit_str("accept"), lit_str("application/grpc-web-text;q=1.001")}},
        {{lit_str("accept"), lit_str("application/grpc-web-text;q=0.1234")}},
        {{lit_str("accept"), lit_str("application/grpc-web-text;q=-0.1")}},
    };
    CHECK_EQ(mode_for(GrpcWebContentType::Binary, text_accept, 1), GrpcWebContentType::Text);
    CHECK_EQ(mode_for(GrpcWebContentType::Text, binary_accept, 1), GrpcWebContentType::Binary);
    CHECK_EQ(mode_for(GrpcWebContentType::Text, wildcard_exclusion, 1), GrpcWebContentType::Binary);
    CHECK_EQ(mode_for(GrpcWebContentType::Binary, text_over_binary_wildcard, 1),
             GrpcWebContentType::Text);
    CHECK_EQ(mode_for(GrpcWebContentType::Text, binary_over_text_wildcard, 1),
             GrpcWebContentType::Binary);
    CHECK_EQ(mode_for(GrpcWebContentType::Binary, duplicate_q, 1), GrpcWebContentType::Other);
    CHECK_EQ(mode_for(GrpcWebContentType::Text, nullptr, 0), GrpcWebContentType::Text);

    struct AcceptCase {
        GrpcWebContentType request_mode;
        const hpack::Header* headers;
        u32 count;
        GrpcWebContentType expected;
    };
    const AcceptCase cases[] = {
        {GrpcWebContentType::Binary, multiple_physical, 2, GrpcWebContentType::Binary},
        {GrpcWebContentType::Binary, ows, 1, GrpcWebContentType::Text},
        {GrpcWebContentType::Text, both_zero, 1, GrpcWebContentType::Other},
        {GrpcWebContentType::Text, unknown_only, 1, GrpcWebContentType::Text},
        {GrpcWebContentType::Binary, same_q_tie, 1, GrpcWebContentType::Binary},
        {GrpcWebContentType::Text, same_q_tie, 1, GrpcWebContentType::Text},
    };
    for (const auto& test : cases)
        CHECK_EQ(mode_for(test.request_mode, test.headers, test.count), test.expected);
    for (const auto& bad_q : bad_q_values)
        CHECK_EQ(mode_for(GrpcWebContentType::Binary, bad_q, 1), GrpcWebContentType::Other);

    struct ModeCase {
        GrpcWebContentType request_mode;
        const hpack::Header* headers;
        GrpcWebContentType expected;
    };
    const ModeCase mode_cases[] = {
        {GrpcWebContentType::Binary, text_accept, GrpcWebContentType::Text},
        {GrpcWebContentType::Text, binary_accept, GrpcWebContentType::Binary}};
    for (const auto& mode_case : mode_cases) {
        GrpcDriveFixture loop;
        Connection downstream;
        downstream.reset();
        Http2Conn downstream_h2;
        downstream_h2.init_client();
        downstream.h2 = &downstream_h2;
        auto* stream = downstream_h2.open_stream(1);
        REQUIRE(stream);
        GrpcExchange x;
        x.init();
        x.web_mode = mode_case.request_mode;
        x.web_response_mode = mode_for(mode_case.request_mode, mode_case.headers, 1);
        CHECK_EQ(x.web_response_mode, mode_case.expected);
        x.downstream = &downstream;
        x.downstream_stream = 1;
        x.response_headers_sent = true;
        const u8 native[] = {0, 0, 0, 0, 0};
        memcpy(x.download, native, sizeof(native));
        x.download_len = sizeof(native);
        REQUIRE(grpc_attach(downstream_h2, &x));

        u8 output[128];
        const u32 output_len = grpc_pump_downstream(&loop, downstream, output, sizeof(output));
        REQUIRE_GT(output_len, 0u);
        REQUIRE_EQ(output[3], static_cast<u8>(Http2FrameType::Data));
        const u32 payload_len =
            (static_cast<u32>(output[0]) << 16) | (static_cast<u32>(output[1]) << 8) | output[2];
        if (mode_case.expected == GrpcWebContentType::Text) {
            u8 decoded[16];
            u32 consumed = 0, written = 0;
            GrpcWebBase64Decoder decoder;
            decoder.init();
            REQUIRE_EQ(decoder.feed(output + kFrameHeaderSize,
                                    payload_len,
                                    consumed,
                                    decoded,
                                    sizeof(decoded),
                                    written),
                       GrpcWebCodecStatus::Ok);
            CHECK_EQ(consumed, payload_len);
            CHECK_EQ(decoder.finish(), GrpcWebCodecStatus::Ok);
            CHECK_EQ(written, sizeof(native));
            CHECK_EQ(memcmp(decoded, native, sizeof(native)), 0);
        } else {
            CHECK_EQ(payload_len, sizeof(native));
            CHECK_EQ(memcmp(output + kFrameHeaderSize, native, sizeof(native)), 0);
        }
        grpc_detach(downstream_h2, &x);
    }
}
TEST(grpc_proxy, request_classifier_rejects_ambiguous_web_content_types) {
    auto classify = [&](Str first, Str second) {
        ParsedRequest req{};
        req.headers[0] = {lit_str("content-type"), first};
        req.headers[1] = {lit_str("content-type"), second};
        req.header_count = 2;
        bool ambiguous = false;
        CHECK_EQ(grpc_request_mode(req, &ambiguous), GrpcWebContentType::Other);
        CHECK(ambiguous);
        CHECK(grpc_request(req));
    };
    classify(lit_str("application/grpc-web"), lit_str("application/grpc"));
    classify(lit_str("application/grpc"), lit_str("application/grpc-web"));
    classify(lit_str("application/grpc-web-text"), lit_str("application/grpc-web"));
    classify(lit_str("application/grpc-web"), lit_str("application/grpc-web+json"));
    classify(lit_str("application/grpc-web+json"), lit_str("application/grpc-web-text"));

    ParsedRequest native{};
    native.headers[0] = {lit_str("content-type"), lit_str("application/grpc+proto")};
    native.headers[1] = {lit_str("content-type"), lit_str("application/grpc+json")};
    native.header_count = 2;
    bool ambiguous = true;
    CHECK_EQ(grpc_request_mode(native, &ambiguous), GrpcWebContentType::Native);
    CHECK_FALSE(ambiguous);
    CHECK(grpc_request(native));

    ParsedRequest unsupported_web{};
    unsupported_web.headers[0] = {lit_str("content-type"), lit_str("application/grpc-web+json")};
    unsupported_web.header_count = 1;
    ambiguous = false;
    CHECK_EQ(grpc_request_mode(unsupported_web, &ambiguous), GrpcWebContentType::Other);
    CHECK(ambiguous);
    CHECK(grpc_request(unsupported_web));
}
TEST(grpc_proxy, response_header_filter_strips_content_length_only) {
    const hpack::Header headers[] = {{Str{"content-length", 14}, Str{"0", 1}},
                                     {Str{"grpc-status", 11}, Str{"0", 1}},
                                     {Str{"x-meta", 6}, Str{"ok", 2}}};
    CHECK(!grpc_response_header_allowed(headers[0]));
    CHECK(grpc_response_header_allowed(headers[1]));
    CHECK(grpc_response_header_allowed(headers[2]));
}
TEST(grpc_proxy, goaway_rejects_unsent_and_above_last_stream) {
    Http2Conn h{};
    h.init();
    h.peer_goaway = true;
    h.peer_last_stream = 5;
    GrpcExchange x{};
    x.init();
    x.upstream_stream = 5;
    CHECK(grpc_rejected_by_goaway(h, x));
    h.peer_last_stream = 0x7fffffffu;
    CHECK(grpc_rejected_by_goaway(h, x));
    x.request_headers_sent = true;
    CHECK(!grpc_rejected_by_goaway(h, x));
    h.peer_last_stream = 5;
    x.upstream_stream = 7;
    CHECK(grpc_rejected_by_goaway(h, x));
}
TEST(grpc_proxy, encoded_goaway_detaches_rejected_exchange_before_client_wakeup) {
    GrpcDriveFixture loop;
    Connection upstream;
    upstream.reset();
    u8 send_storage[512]{};
    upstream.send_slice = send_storage;
    upstream.send_buf.bind(send_storage, sizeof(send_storage));
    u8 recv_storage[64]{};
    upstream.recv_slice = recv_storage;
    upstream.recv_buf.bind(recv_storage, sizeof(recv_storage));
    Http2Conn upstream_h2;
    upstream_h2.init_client();
    upstream_h2.preface_seen = true;
    upstream_h2.our_settings_sent = true;
    upstream_h2.peer_settings_seen = true;
    upstream_h2.grpc.upstream = true;
    upstream.h2 = &upstream_h2;
    Connection downstream;
    downstream.reset();
    u8 downstream_send_storage[512]{};
    downstream.send_slice = downstream_send_storage;
    downstream.send_buf.bind(downstream_send_storage, sizeof(downstream_send_storage));
    Http2Conn downstream_h2;
    downstream_h2.init_client();
    downstream.h2 = &downstream_h2;
    downstream.on_send = &pending_send;
    auto* x = reinterpret_cast<GrpcExchange*>(loop.pool.alloc_bulk());
    REQUIRE(x != nullptr);
    x->init();
    x->upstream = &upstream;
    x->downstream = &downstream;
    x->upstream_stream = x->downstream_stream = 1;
    x->upstream_id = 0;
    x->slot_held = true;
    REQUIRE(upstream_h2.open_stream(1) != nullptr);
    REQUIRE(downstream_h2.open_stream(1) != nullptr);
    REQUIRE(grpc_attach(upstream_h2, x));
    REQUIRE(grpc_attach(downstream_h2, x));
    const u32 frame_len = write_goaway(recv_storage, 0, Http2Error::NoError);
    upstream.recv_buf.commit(frame_len);
    grpc_on_upstream_data<GrpcDriveFixture>(
        &loop, upstream, {upstream.id, static_cast<i32>(frame_len), 0, 0, IoEventType::Recv, 0});
    CHECK_EQ(x->failure, 14u);
    CHECK(x->response_end);
    CHECK(x->upstream == nullptr);
    CHECK_EQ(upstream_h2.grpc.active, 0u);
    CHECK_EQ(loop.released, 1u);
    CHECK_EQ(downstream_h2.grpc.active, 1u);
}
TEST(grpc_proxy, encoded_reset_skips_stale_downstream_snapshot_after_sync_close) {
    SyncCloseGrpcDriveFixture loop;
    Connection upstream;
    upstream.reset();
    u8 send_storage[512]{};
    upstream.send_slice = send_storage;
    upstream.send_buf.bind(send_storage, sizeof(send_storage));
    u8 recv_storage[64]{};
    upstream.recv_slice = recv_storage;
    upstream.recv_buf.bind(recv_storage, sizeof(recv_storage));
    Http2Conn upstream_h2;
    upstream_h2.init_client();
    upstream_h2.preface_seen = true;
    upstream_h2.our_settings_sent = true;
    upstream_h2.peer_settings_seen = true;
    upstream_h2.grpc.upstream = true;
    upstream.h2 = &upstream_h2;
    Connection downstream;
    downstream.reset();
    u8 downstream_send_storage[512]{};
    auto* downstream_recv_storage = loop.pool.alloc();
    REQUIRE(downstream_recv_storage != nullptr);
    downstream.send_slice = downstream_send_storage;
    downstream.send_buf.bind(downstream_send_storage, sizeof(downstream_send_storage));
    downstream.bind_request_receive_buffer(downstream_recv_storage, SlicePool::kSliceSize);
    Http2Conn downstream_h2;
    downstream_h2.init_client();
    downstream.h2 = &downstream_h2;
    downstream.on_close = &grpc_connection_closed<SyncCloseGrpcDriveFixture>;
    auto* x = reinterpret_cast<GrpcExchange*>(loop.pool.alloc_bulk());
    REQUIRE(x != nullptr);
    x->init();
    x->upstream = &upstream;
    x->downstream = &downstream;
    x->upstream_stream = x->downstream_stream = 1;
    x->upstream_id = 0;
    x->slot_held = true;
    REQUIRE(upstream_h2.open_stream(1) != nullptr);
    REQUIRE(downstream_h2.open_stream(1) != nullptr);
    REQUIRE(grpc_attach(upstream_h2, x));
    REQUIRE(grpc_attach(downstream_h2, x));
    const u32 frame_len = write_rst_stream(recv_storage, 1, Http2Error::Cancel);
    upstream.recv_buf.commit(frame_len);
    grpc_on_upstream_data<SyncCloseGrpcDriveFixture>(
        &loop, upstream, {upstream.id, static_cast<i32>(frame_len), 0, 0, IoEventType::Recv, 0});
    CHECK(loop.closed);
    CHECK(downstream.h2 == nullptr);
    CHECK_EQ(upstream_h2.grpc.active, 0u);
    CHECK_EQ(loop.released, 1u);
}
TEST(grpc_proxy, deadline_cascade_handles_upstream_sync_close_safely) {
    SyncCloseGrpcDriveFixture loop;
    Connection upstream;
    upstream.reset();
    u8 upstream_send[512]{};
    u8 upstream_recv[512]{};
    upstream.send_slice = upstream_send;
    upstream.send_buf.bind(upstream_send, sizeof(upstream_send));
    upstream.recv_slice = upstream_recv;
    upstream.recv_buf.bind(upstream_recv, sizeof(upstream_recv));
    Http2Conn upstream_h2;
    upstream_h2.init_client();
    upstream_h2.grpc.upstream = true;
    upstream_h2.grpc.preface_sent = true;
    upstream_h2.peer_settings_seen = true;
    upstream.h2 = &upstream_h2;
    upstream.on_close = &grpc_connection_closed<SyncCloseGrpcDriveFixture>;
    Connection downs[2];
    Http2Conn down_h2[2];
    u8 down_send[2][512]{};
    for (u32 i = 0; i < 2; i++) {
        downs[i].reset();
        downs[i].send_slice = down_send[i];
        downs[i].send_buf.bind(down_send[i], sizeof(down_send[i]));
        auto* recv = loop.pool.alloc();
        REQUIRE(recv != nullptr);
        downs[i].bind_request_receive_buffer(recv, SlicePool::kSliceSize);
        down_h2[i].init_client();
        downs[i].h2 = &down_h2[i];
        downs[i].on_close = &grpc_connection_closed<SyncCloseGrpcDriveFixture>;
        REQUIRE(down_h2[i].open_stream(1) != nullptr);
        if (i == 0) REQUIRE(down_h2[i].open_stream(3) != nullptr);
    }
    REQUIRE(upstream_h2.open_stream(1) != nullptr);
    REQUIRE(upstream_h2.open_stream(3) != nullptr);
    auto* expired = reinterpret_cast<GrpcExchange*>(loop.pool.alloc_bulk());
    auto* active = reinterpret_cast<GrpcExchange*>(loop.pool.alloc_bulk());
    REQUIRE(expired != nullptr);
    REQUIRE(active != nullptr);
    expired->init();
    active->init();
    GrpcExchange* exchanges[] = {expired, active};
    for (u32 i = 0; i < 2; i++) {
        auto* x = exchanges[i];
        x->upstream = &upstream;
        x->downstream = &downs[0];
        x->upstream_stream = i ? 3 : 1;
        x->downstream_stream = i ? 3 : 1;
        x->upstream_id = i;
        x->slot_held = true;
        x->request_headers_sent = true;
        REQUIRE(grpc_attach(upstream_h2, x));
        REQUIRE(grpc_attach(*downs[0].h2, x));
    }
    expired->deadline_us = monotonic_us() - 1;
    active->deadline_us = monotonic_us() + 1000000;
    grpc_deadline_fired(&loop, downs[0]);
    CHECK(loop.closed);
    CHECK(downs[0].h2 == nullptr);
    CHECK_EQ(upstream_h2.grpc.active, 0u);
    CHECK_EQ(loop.released, 2u);
}
TEST(grpc_proxy, timer_arm_failure_cascade_handles_upstream_sync_close_safely) {
    SyncCloseGrpcDriveFixture loop;
    Connection upstream;
    upstream.reset();
    u8 upstream_send[512]{};
    u8 upstream_recv[512]{};
    upstream.send_slice = upstream_send;
    upstream.send_buf.bind(upstream_send, sizeof(upstream_send));
    upstream.recv_slice = upstream_recv;
    upstream.recv_buf.bind(upstream_recv, sizeof(upstream_recv));
    Http2Conn upstream_h2;
    upstream_h2.init_client();
    upstream_h2.grpc.upstream = true;
    upstream_h2.grpc.preface_sent = true;
    upstream_h2.peer_settings_seen = true;
    upstream.h2 = &upstream_h2;
    upstream.on_close = &grpc_connection_closed<SyncCloseGrpcDriveFixture>;
    Connection downs[2];
    Http2Conn down_h2[2];
    u8 down_send[2][512]{};
    for (u32 i = 0; i < 2; i++) {
        downs[i].reset();
        downs[i].send_slice = down_send[i];
        downs[i].send_buf.bind(down_send[i], sizeof(down_send[i]));
        auto* recv = loop.pool.alloc();
        REQUIRE(recv != nullptr);
        downs[i].bind_request_receive_buffer(recv, SlicePool::kSliceSize);
        down_h2[i].init_client();
        downs[i].h2 = &down_h2[i];
        downs[i].on_close = &grpc_connection_closed<SyncCloseGrpcDriveFixture>;
        REQUIRE(down_h2[i].open_stream(1) != nullptr);
        if (i == 0) REQUIRE(down_h2[i].open_stream(3) != nullptr);
    }
    REQUIRE(upstream_h2.open_stream(1) != nullptr);
    REQUIRE(upstream_h2.open_stream(3) != nullptr);
    auto* expired = reinterpret_cast<GrpcExchange*>(loop.pool.alloc_bulk());
    auto* active = reinterpret_cast<GrpcExchange*>(loop.pool.alloc_bulk());
    REQUIRE(expired != nullptr);
    REQUIRE(active != nullptr);
    expired->init();
    active->init();
    GrpcExchange* exchanges[] = {expired, active};
    for (u32 i = 0; i < 2; i++) {
        auto* x = exchanges[i];
        x->upstream = &upstream;
        x->downstream = &downs[0];
        x->upstream_stream = i ? 3 : 1;
        x->downstream_stream = i ? 3 : 1;
        x->upstream_id = i;
        x->slot_held = true;
        x->request_headers_sent = true;
        REQUIRE(grpc_attach(upstream_h2, x));
        REQUIRE(grpc_attach(*downs[0].h2, x));
    }
    expired->deadline_us = monotonic_us() + 1000000;
    active->deadline_us = monotonic_us() + 1000000;
    grpc_refresh_timer(&loop, downs[0]);
    CHECK(loop.closed);
    CHECK(downs[0].h2 == nullptr);
    CHECK_EQ(upstream_h2.grpc.active, 0u);
    CHECK_EQ(loop.released, 2u);
}
TEST(grpc_proxy, idle_since_refreshes_after_long_active_session) {
    Http2Conn h{};
    h.init();
    GrpcExchange x{};
    x.init();
    h.grpc.active = 1;
    h.grpc.streams[0] = &x;
    h.grpc.idle_since_us = 10;
    grpc_detach(h, &x);
    CHECK_EQ(h.grpc.active, 0u);
    CHECK_GT(h.grpc.idle_since_us, 10u);
    CHECK(!grpc_idle_upstream_should_close(h.grpc, false, false, h.grpc.idle_since_us + 999, 1000));
    CHECK(grpc_idle_upstream_should_close(h.grpc, false, false, h.grpc.idle_since_us + 1000, 1000));
}
TEST(grpc_proxy, handshake_timestamp_is_immutable_when_joining) {
    GrpcProxyState g{};
    g.init();
    grpc_begin_handshake(g, 100);
    grpc_begin_handshake(g, 200);
    CHECK_EQ(g.connected_at_us, 100u);
}
TEST(grpc_proxy, repeated_settings_success_does_not_clear_active_rpc_failures) {
    GrpcBackendHealthReset health_reset{};
    auto* health = backend_health(0, 0);
    REQUIRE(health != nullptr);
    Connection conn;
    conn.reset();
    Http2Conn h2;
    h2.init();
    h2.grpc.upstream = true;
    h2.grpc.active = 1;
    conn.h2 = &h2;
    conn.upstream_idx = 0;
    conn.upstream_backend_idx = 0;
    GrpcDriveFixture loop;
    for (u32 i = 0; i < kBackendFailThreshold; i++) {
        h2.grpc.session_failure_recorded = false;
        h2.peer_settings_seen = false;
        h2.grpc.connected_at_us = 1;
        loop.closed = false;
        grpc_tick(&loop, conn);
        CHECK(loop.closed);
    }
    CHECK_EQ(health->fails, kBackendFailThreshold);
    CHECK(backend_ejected(0, 0, monotonic_us()));
    h2.peer_settings_seen = true;
    grpc_record_handshake_result(conn, true, monotonic_us());
    grpc_record_handshake_result(conn, true, monotonic_us());
    CHECK_EQ(health->fails, kBackendFailThreshold);
}
TEST(grpc_proxy, upstream_send_failure_records_handshake_health_once) {
    GrpcBackendHealthReset health_reset{};
    auto* health = backend_health(0, 0);
    REQUIRE(health != nullptr);
    GrpcDriveFixture loop;
    for (u32 i = 0; i < kBackendFailThreshold; i++) {
        Connection conn;
        conn.reset();
        Http2Conn h2;
        h2.init_client();
        h2.grpc.upstream = true;
        h2.grpc.active = 1;
        h2.peer_settings_seen = false;
        conn.h2 = &h2;
        conn.upstream_idx = 0;
        conn.upstream_backend_idx = 0;
        loop.closed = false;
        grpc_on_upstream_sent<GrpcDriveFixture>(
            &loop, conn, {conn.id, -EPIPE, 0, 0, IoEventType::Send, 0});
        CHECK(loop.closed);
        CHECK_EQ(health->fails, i + 1);
        CHECK(backend_ejected(0, 0, monotonic_us()) == (i + 1 >= kBackendFailThreshold));
        grpc_on_upstream_sent<GrpcDriveFixture>(
            &loop, conn, {conn.id, -EPIPE, 0, 0, IoEventType::Send, 0});
        CHECK_EQ(health->fails, i + 1);
    }
    CHECK_EQ(health->fails, kBackendFailThreshold);
    CHECK(backend_ejected(0, 0, monotonic_us()));

    Connection settings_conn;
    settings_conn.reset();
    Http2Conn settings_h2;
    settings_h2.init_client();
    settings_h2.grpc.upstream = true;
    settings_h2.peer_settings_seen = true;
    settings_conn.h2 = &settings_h2;
    settings_conn.upstream_idx = 0;
    settings_conn.upstream_backend_idx = 0;
    loop.closed = false;
    grpc_on_upstream_sent<GrpcDriveFixture>(
        &loop, settings_conn, {settings_conn.id, -EPIPE, 0, 0, IoEventType::Send, 0});
    CHECK(loop.closed);
    CHECK_EQ(health->fails, kBackendFailThreshold);
}

TEST(grpc_proxy, stale_handshake_result_does_not_touch_reloaded_backend) {
    GrpcBackendHealthReset health_reset{};
    auto* health = backend_health(0, 0);
    REQUIRE(health != nullptr);
    RouteConfig old_config;
    RouteConfig current_config;
    const RouteConfig* active = &current_config;
    GrpcDriveFixture loop;
    loop.config_ptr = &active;
    Connection conn;
    conn.reset();
    Http2Conn h2;
    h2.init_client();
    h2.grpc.upstream = true;
    conn.h2 = &h2;
    conn.request_config = &old_config;
    conn.upstream_idx = 0;
    conn.upstream_backend_idx = 0;
    grpc_record_handshake_result(&loop, conn, false, monotonic_us());
    CHECK_EQ(health->fails, 0u);
    active = &old_config;
    grpc_record_handshake_result(&loop, conn, false, monotonic_us());
    CHECK_EQ(health->fails, 1u);
}

TEST(grpc_proxy, stale_connect_failure_does_not_touch_reloaded_backend) {
    GrpcBackendHealthReset health_reset{};
    auto* health = backend_health(0, 0);
    REQUIRE(health != nullptr);
    RouteConfig old_config;
    RouteConfig current_config;
    const RouteConfig* active = &current_config;
    GrpcDriveFixture loop;
    loop.config_ptr = &active;
    Connection conn;
    conn.reset();
    Http2Conn h2;
    h2.init_client();
    h2.grpc.upstream = true;
    conn.h2 = &h2;
    conn.request_config = &old_config;
    conn.upstream_idx = 0;
    conn.upstream_backend_idx = 0;
    grpc_connected<GrpcDriveFixture>(&loop, conn, {conn.id, -111, 0, 0, IoEventType::Recv, 0});
    CHECK_EQ(health->fails, 0u);
    active = &old_config;
    loop.closed = false;
    grpc_connected<GrpcDriveFixture>(&loop, conn, {conn.id, -111, 0, 0, IoEventType::Recv, 0});
    CHECK_EQ(health->fails, 1u);
}
TEST(grpc_proxy, stale_idle_upstream_closes_but_active_old_config_drains) {
    RouteConfig old_config;
    RouteConfig current_config;
    const RouteConfig* active = &current_config;
    GrpcDriveFixture loop;
    loop.config_ptr = &active;
    Connection conn;
    conn.reset();
    Http2Conn h2;
    h2.init_client();
    h2.grpc.upstream = true;
    h2.grpc.idle_since_us = monotonic_us();
    h2.grpc.connected_at_us = h2.grpc.idle_since_us;
    conn.h2 = &h2;
    conn.request_config = &old_config;
    grpc_tick(&loop, conn);
    CHECK(loop.closed);

    loop.closed = false;
    h2.grpc.active = 1;
    grpc_tick(&loop, conn);
    CHECK_FALSE(loop.closed);
}

TEST(grpc_proxy, invalid_initial_response_headers_detach_upstream_exchange) {
    GrpcDriveFixture loop;
    Connection upstream;
    upstream.reset();
    Http2Conn upstream_h2;
    upstream_h2.init_client();
    upstream_h2.grpc.upstream = true;
    upstream.h2 = &upstream_h2;
    Connection downstream;
    downstream.reset();
    Http2Conn downstream_h2;
    downstream_h2.init_client();
    downstream.h2 = &downstream_h2;
    GrpcExchange x;
    x.init();
    x.upstream = &upstream;
    x.downstream = &downstream;
    x.upstream_stream = 1;
    x.downstream_stream = 1;
    x.slot_held = true;
    x.upstream_id = 7;
    x.request_headers_sent = true;
    REQUIRE(upstream_h2.open_stream(1) != nullptr);
    REQUIRE(downstream_h2.open_stream(1) != nullptr);
    REQUIRE(grpc_attach(upstream_h2, &x));
    REQUIRE(grpc_attach(downstream_h2, &x));
    GrpcClientDispatch<GrpcDriveFixture> dispatch{&loop, &upstream};
    const hpack::Header headers[] = {
        {{":status", 7}, {"503", 3}},
        {{"content-type", 12}, {"text/plain", 10}},
    };
    grpc_response_headers<GrpcDriveFixture>(&dispatch, upstream_h2, 1, headers, 2, false);
    CHECK_EQ(x.failure, 14u);
    CHECK(x.response_end);
    CHECK(x.upstream == nullptr);
    CHECK_EQ(upstream_h2.grpc.active, 0u);
    CHECK_EQ(loop.released, 1u);
    CHECK_EQ(upstream_h2.grpc.control_len, 13u);
    u8 out[512];
    const u32 sent = grpc_pump_downstream(&loop, downstream, out, sizeof(out));
    CHECK_GT(sent, 0u);
}

TEST(grpc_proxy, response_header_staging_failure_detaches_exchange) {
    GrpcDriveFixture loop;
    Connection upstream;
    upstream.reset();
    Http2Conn upstream_h2;
    upstream_h2.init_client();
    upstream_h2.grpc.upstream = true;
    upstream.h2 = &upstream_h2;
    Connection downstream;
    downstream.reset();
    Http2Conn downstream_h2;
    downstream_h2.init_client();
    downstream.h2 = &downstream_h2;
    downstream.on_send = &pending_send;
    GrpcExchange x;
    x.init();
    x.upstream = &upstream;
    x.downstream = &downstream;
    x.upstream_stream = x.downstream_stream = 1;
    x.slot_held = true;
    x.request_headers_sent = true;
    REQUIRE(upstream_h2.open_stream(1) != nullptr);
    REQUIRE(downstream_h2.open_stream(1) != nullptr);
    REQUIRE(grpc_attach(upstream_h2, &x));
    REQUIRE(grpc_attach(downstream_h2, &x));

    hpack::Header headers[2];
    headers[0] = {{":status", 7}, {"200", 3}};
    headers[1] = {{"content-type", 12}, {"application/grpc", 16}};
    static constexpr char alphabet[] = "!#$%&'()*+,-./:;<=>?@[]^_`{|}~";
    x.response_mutation_count = 16;
    for (u32 i = 0; i < x.response_mutation_count; i++) {
        const u32 offset = i * 1024;
        for (u32 j = 0; j < 14; j++)
            x.response_mutation_storage[offset + j] = static_cast<u8>('a' + ((j + i) % 26));
        u32 state = i + 1;
        for (u32 j = 0; j < 1010; j++) {
            state = state * 1664525u + 1013904223u;
            x.response_mutation_storage[offset + 14 + j] = alphabet[state % (sizeof(alphabet) - 1)];
        }
        x.response_mutations[i] = {static_cast<u16>(offset),
                                   14,
                                   static_cast<u16>(offset + 14),
                                   1010,
                                   static_cast<u8>(Connection::RespHeaderMutationMode::Add)};
    }
    hpack::Header validated[64];
    validated[0] = headers[0];
    validated[1] = headers[1];
    u32 validated_count = 2;
    REQUIRE(grpc_apply_response_mutations(x, validated, &validated_count, 64));
    GrpcClientDispatch<GrpcDriveFixture> dispatch{&loop, &upstream};
    grpc_response_headers<GrpcDriveFixture>(&dispatch, upstream_h2, 1, headers, 2, false);
    CHECK_EQ(x.failure, 8u);
    CHECK(x.response_end);
    CHECK(x.upstream == nullptr);
    CHECK_EQ(upstream_h2.grpc.active, 0u);
    CHECK_EQ(loop.released, 1u);
    CHECK_EQ(upstream_h2.grpc.control_len, 13u);
}

TEST(grpc_proxy, response_content_length_is_validated_across_grpc_end_states) {
    auto run = [&_tc](const hpack::Header* headers,
                      u32 header_count,
                      bool header_end,
                      const u8* data,
                      u32 data_len,
                      bool data_end,
                      const hpack::Header* trailers,
                      u32 trailer_count,
                      u8 expected_failure,
                      bool expect_detached) {
        GrpcDriveFixture loop;
        Connection upstream;
        upstream.reset();
        Http2Conn upstream_h2;
        upstream_h2.init_client();
        upstream_h2.grpc.upstream = true;
        upstream.h2 = &upstream_h2;
        Connection downstream;
        downstream.reset();
        Http2Conn downstream_h2;
        downstream_h2.init_client();
        downstream.h2 = &downstream_h2;
        GrpcExchange x;
        x.init();
        x.upstream = &upstream;
        x.downstream = &downstream;
        x.upstream_stream = x.downstream_stream = 1;
        x.slot_held = true;
        x.upstream_id = 7;
        REQUIRE(upstream_h2.open_stream(1) != nullptr);
        REQUIRE(downstream_h2.open_stream(1) != nullptr);
        REQUIRE(grpc_attach(upstream_h2, &x));
        REQUIRE(grpc_attach(downstream_h2, &x));
        GrpcClientDispatch<GrpcDriveFixture> dispatch{&loop, &upstream};
        grpc_response_headers<GrpcDriveFixture>(
            &dispatch, upstream_h2, 1, headers, header_count, header_end);
        if (data_len)
            grpc_response_data<GrpcDriveFixture>(
                &dispatch, upstream_h2, 1, data, data_len, data_end);
        if (trailers)
            grpc_response_trailers<GrpcDriveFixture>(
                &dispatch, upstream_h2, 1, trailers, trailer_count, true);
        CHECK_EQ(x.failure, expected_failure);
        if (expect_detached) CHECK(x.upstream == nullptr);
    };
    const hpack::Header exact_headers[] = {
        {{":status", 7}, {"200", 3}},
        {{"content-type", 12}, {"application/grpc", 16}},
        {{"content-length", 14}, {"3", 1}},
    };
    const hpack::Header status_trailers[] = {{{"grpc-status", 11}, {"0", 1}}};
    const u8 abc[] = {'a', 'b', 'c'};
    run(exact_headers, 3, false, abc, 3, false, status_trailers, 1, 0, false);
    run(exact_headers, 3, false, abc, 3, false, nullptr, 0, 0, false);
    run(exact_headers, 3, false, abc, 3, true, nullptr, 0, 2, false);

    const hpack::Header short_headers[] = {
        {{":status", 7}, {"200", 3}},
        {{"content-type", 12}, {"application/grpc", 16}},
        {{"content-length", 14}, {"4", 1}},
    };
    run(short_headers, 3, false, abc, 3, false, status_trailers, 1, 13, false);

    const hpack::Header long_headers[] = {
        {{":status", 7}, {"200", 3}},
        {{"content-type", 12}, {"application/grpc", 16}},
        {{"content-length", 14}, {"2", 1}},
    };
    run(long_headers, 3, false, abc, 3, false, nullptr, 0, 13, false);

    const hpack::Header malformed_headers[] = {
        {{":status", 7}, {"200", 3}},
        {{"content-type", 12}, {"application/grpc", 16}},
        {{"content-length", 14}, {"nope", 4}},
    };
    run(malformed_headers, 3, false, nullptr, 0, false, nullptr, 0, 13, true);

    const hpack::Header duplicate_headers[] = {
        {{":status", 7}, {"200", 3}},
        {{"content-type", 12}, {"application/grpc", 16}},
        {{"content-length", 14}, {"3", 1}},
        {{"content-length", 14}, {"3", 1}},
    };
    run(duplicate_headers, 4, false, nullptr, 0, false, nullptr, 0, 13, true);

    const hpack::Header overflow_headers[] = {
        {{":status", 7}, {"200", 3}},
        {{"content-type", 12}, {"application/grpc", 16}},
        {{"content-length", 14}, {"4294967296", 10}},
    };
    run(overflow_headers, 3, false, nullptr, 0, false, nullptr, 0, 13, true);

    const hpack::Header terminal_headers[] = {
        {{":status", 7}, {"200", 3}},
        {{"content-type", 12}, {"application/grpc", 16}},
        {{"content-length", 14}, {"1", 1}},
        {{"grpc-status", 11}, {"0", 1}},
    };
    run(terminal_headers, 4, true, nullptr, 0, false, nullptr, 0, 13, false);
}

TEST(grpc_proxy, encoded_terminal_response_releases_stream_slot_for_queued_rpc) {
    GrpcDriveFixture loop;
    Connection upstream;
    upstream.reset();
    u8 recv[512]{};
    u8 send[512]{};
    upstream.bind_request_receive_buffer(recv, sizeof(recv));
    upstream.send_slice = send;
    upstream.send_buf.bind(send, sizeof(send));
    Http2Conn upstream_h2;
    upstream_h2.init_client();
    upstream_h2.grpc.upstream = true;
    upstream_h2.peer_settings_seen = true;
    upstream_h2.peer_settings.has_max_concurrent_streams = true;
    upstream_h2.peer_settings.max_concurrent_streams = 1;
    upstream.h2 = &upstream_h2;

    Connection downstream;
    downstream.reset();
    u8 downstream_send[512]{};
    downstream.send_slice = downstream_send;
    downstream.send_buf.bind(downstream_send, sizeof(downstream_send));
    Http2Conn downstream_h2;
    downstream_h2.init_client();
    downstream.h2 = &downstream_h2;
    REQUIRE(upstream_h2.open_stream(1) != nullptr);
    REQUIRE(upstream_h2.open_stream(3) != nullptr);
    REQUIRE(downstream_h2.open_stream(1) != nullptr);
    REQUIRE(downstream_h2.open_stream(3) != nullptr);

    upstream_h2.find_stream(1)->state = Http2StreamState::HalfClosedLocal;
    downstream.on_send = &pending_send;
    auto* terminal = reinterpret_cast<GrpcExchange*>(loop.pool.alloc_bulk());
    auto* queued = reinterpret_cast<GrpcExchange*>(loop.pool.alloc_bulk());
    REQUIRE(terminal != nullptr);
    REQUIRE(queued != nullptr);
    terminal->init();
    queued->init();
    terminal->upstream = queued->upstream = &upstream;
    terminal->downstream = queued->downstream = &downstream;
    terminal->upstream_stream = terminal->downstream_stream = 1;
    queued->upstream_stream = queued->downstream_stream = 3;
    terminal->slot_held = queued->slot_held = true;
    terminal->request_end_sent = true;
    terminal->request_headers_sent = true;
    const hpack::Header request[] = {{{":method", 7}, {"POST", 4}}, {{":path", 5}, {"/", 1}}};
    queued->request_headers_len = http2_write_headers(
        queued->request_headers, sizeof(queued->request_headers), 3, request, 2, false);
    REQUIRE(queued->request_headers_len > 0);
    REQUIRE(grpc_attach(upstream_h2, terminal));
    REQUIRE(grpc_attach(upstream_h2, queued));
    REQUIRE(grpc_attach(downstream_h2, terminal));
    REQUIRE(grpc_attach(downstream_h2, queued));

    const hpack::Header response[] = {{{":status", 7}, {"200", 3}},
                                      {{"content-type", 12}, {"application/grpc", 16}},
                                      {{"grpc-status", 11}, {"0", 1}}};
    const u32 response_len = http2_write_headers(recv, sizeof(recv), 1, response, 3, true);
    upstream.recv_buf.commit(response_len);
    grpc_on_upstream_data<GrpcDriveFixture>(
        &loop, upstream, {upstream.id, static_cast<i32>(response_len), 0, 0, IoEventType::Recv, 1});
    CHECK(upstream_h2.find_stream(1) == nullptr);
    CHECK_EQ(upstream_h2.grpc.active, 2u);
    CHECK_GT(loop.sends, 0u);
    grpc_on_upstream_sent<GrpcDriveFixture>(
        &loop,
        upstream,
        {upstream.id, static_cast<i32>(upstream.send_buf.len()), 0, 0, IoEventType::Send, 0});
    CHECK(queued->request_headers_sent);
}

TEST(grpc_proxy, upstream_settings_health_uses_actual_h2_processing_order) {
    GrpcBackendHealthReset health_reset{};
    auto* health = backend_health(0, 0);
    REQUIRE(health != nullptr);
    GrpcDriveFixture loop;
    auto run = [&](u8* bytes, u32 len, bool expect_close, bool expect_settings_seen) {
        Connection conn;
        conn.reset();
        u8 recv[512]{};
        u8 send[512]{};
        REQUIRE(len <= sizeof(recv));
        for (u32 i = 0; i < len; i++) recv[i] = bytes[i];
        conn.bind_request_receive_buffer(recv, sizeof(recv));
        conn.send_slice = send;
        conn.send_buf.bind(send, sizeof(send));
        conn.recv_buf.commit(len);
        Http2Conn h2;
        h2.init_client();
        h2.preface_seen = true;
        h2.our_settings_sent = true;
        h2.grpc.upstream = true;
        h2.grpc.active = 1;
        h2.grpc.preface_sent = true;
        conn.h2 = &h2;
        conn.upstream_idx = 0;
        conn.upstream_backend_idx = 0;
        loop.closed = false;
        grpc_on_upstream_data<GrpcDriveFixture>(
            &loop, conn, {conn.id, 1, 0, 0, IoEventType::Recv, 1});
        for (u32 pass = 0; pass < 2 && conn.recv_buf.len() && !loop.closed; pass++)
            grpc_on_upstream_data<GrpcDriveFixture>(
                &loop, conn, {conn.id, 1, 0, 0, IoEventType::Recv, 1});
        CHECK_EQ(loop.closed, expect_close);
        CHECK_EQ(h2.peer_settings_seen, expect_settings_seen);
    };
    Http2FrameHeader invalid{};
    invalid.length = 1;
    invalid.type = static_cast<u8>(Http2FrameType::Settings);
    u8 bad[64]{};
    write_frame_header(bad, invalid);
    bad[9] = 0;
    run(bad, 10, true, false);
    CHECK_EQ(health->fails, 1u);
    u8 bad_value[64]{};
    Http2FrameHeader bad_value_header{};
    bad_value_header.length = 6;
    bad_value_header.type = static_cast<u8>(Http2FrameType::Settings);
    write_frame_header(bad_value, bad_value_header);
    bad_value[9] = 0;
    bad_value[10] = 2;
    bad_value[14] = 2;
    run(bad_value, 15, true, false);
    run(bad, 10, true, false);
    CHECK_EQ(health->fails, kBackendFailThreshold);
    CHECK(backend_ejected(0, 0, monotonic_us()));

    Http2Settings settings;
    settings.set_defaults();
    u8 mixed[128]{};
    u32 mixed_len = write_settings_frame(mixed, settings);
    write_frame_header(mixed + mixed_len, invalid);
    mixed[mixed_len + 9] = 0;
    mixed_len += 10;
    run(mixed, mixed_len, true, true);
    CHECK_EQ(health->fails, kBackendFailThreshold);

    u8 good[64]{};
    const u32 good_len = write_settings_frame(good, settings);
    run(good, good_len, false, true);
    CHECK_EQ(health->fails, kBackendFailThreshold);
}

TEST(grpc_proxy, accepted_unfinished_rpc_eof_ejects_fresh_sessions) {
    GrpcBackendHealthReset health_reset{};
    auto* health = backend_health(0, 0);
    REQUIRE(health != nullptr);
    GrpcDriveFixture loop;
    Http2Settings settings;
    settings.set_defaults();

    for (u32 attempt = 0; attempt < kBackendFailThreshold; attempt++) {
        Connection conn;
        conn.reset();
        u8 recv[128]{};
        u8 send[512]{};
        conn.bind_request_receive_buffer(recv, sizeof(recv));
        conn.send_slice = send;
        conn.send_buf.bind(send, sizeof(send));
        const u32 settings_len = write_settings_frame(recv, settings);
        conn.recv_buf.commit(settings_len);
        Http2Conn h2;
        h2.init_client();
        h2.preface_seen = true;
        h2.our_settings_sent = true;
        h2.grpc.upstream = true;
        h2.grpc.preface_sent = true;
        conn.h2 = &h2;
        conn.upstream_idx = 0;
        conn.upstream_backend_idx = 0;
        REQUIRE(h2.open_stream(1) != nullptr);
        GrpcExchange exchange;
        exchange.init();
        exchange.upstream = &conn;
        exchange.upstream_stream = 1;
        exchange.request_headers_sent = true;
        REQUIRE(grpc_attach(h2, &exchange));

        loop.closed = false;
        grpc_on_upstream_data<GrpcDriveFixture>(
            &loop, conn, {conn.id, static_cast<i32>(settings_len), 0, 0, IoEventType::Recv, 1});
        CHECK_FALSE(loop.closed);
        CHECK(h2.peer_settings_seen);
        grpc_on_upstream_data<GrpcDriveFixture>(
            &loop, conn, {conn.id, 0, 0, 0, IoEventType::Recv, 0});
        CHECK(loop.closed);
        CHECK_EQ(health->fails, attempt + 1);
    }
    CHECK_EQ(health->fails, kBackendFailThreshold);
    CHECK(backend_ejected(0, 0, monotonic_us()));
}

TEST(grpc_proxy, terminal_rpc_clears_then_accepted_eof_counts_once) {
    GrpcBackendHealthReset health_reset{};
    auto* health = backend_health(0, 0);
    REQUIRE(health != nullptr);
    health->fails = 2;
    GrpcDriveFixture loop;
    Connection upstream;
    upstream.reset();
    upstream.upstream_idx = 0;
    upstream.upstream_backend_idx = 0;
    Http2Conn upstream_h2;
    upstream_h2.init_client();
    upstream_h2.grpc.upstream = true;
    upstream_h2.peer_settings_seen = true;
    upstream.h2 = &upstream_h2;
    Connection downstream;
    downstream.reset();
    Http2Conn downstream_h2;
    downstream_h2.init_client();
    downstream.h2 = &downstream_h2;
    REQUIRE(upstream_h2.open_stream(1) != nullptr);
    REQUIRE(downstream_h2.open_stream(1) != nullptr);
    auto* first = reinterpret_cast<GrpcExchange*>(loop.pool.alloc_bulk());
    REQUIRE(first != nullptr);
    first->init();
    first->upstream = &upstream;
    first->downstream = &downstream;
    first->upstream_stream = first->downstream_stream = 1;
    first->request_headers_sent = true;
    REQUIRE(grpc_attach(upstream_h2, first));
    REQUIRE(grpc_attach(downstream_h2, first));
    GrpcClientDispatch<GrpcDriveFixture> dispatch{&loop, &upstream};
    const hpack::Header terminal[] = {
        {{":status", 7}, {"200", 3}},
        {{"content-type", 12}, {"application/grpc", 16}},
        {{"grpc-status", 11}, {"7", 1}},
    };
    grpc_response_headers<GrpcDriveFixture>(&dispatch, upstream_h2, 1, terminal, 3, true);
    CHECK_EQ(health->fails, 0u);
    CHECK(first->response_end);

    REQUIRE(upstream_h2.open_stream(3) != nullptr);
    auto* second = reinterpret_cast<GrpcExchange*>(loop.pool.alloc_bulk());
    REQUIRE(second != nullptr);
    second->init();
    second->upstream = &upstream;
    second->upstream_stream = 3;
    second->request_headers_sent = true;
    REQUIRE(grpc_attach(upstream_h2, second));
    loop.closed = false;
    grpc_on_upstream_data<GrpcDriveFixture>(
        &loop, upstream, {upstream.id, 0, 0, 0, IoEventType::Recv, 0});
    CHECK(loop.closed);
    CHECK_EQ(health->fails, 1u);
}

TEST(grpc_proxy, session_failure_excludes_idle_goaway_and_stale_config) {
    GrpcBackendHealthReset health_reset{};
    auto* health = backend_health(0, 0);
    REQUIRE(health != nullptr);
    GrpcDriveFixture loop;
    RouteConfig current_config;
    RouteConfig stale_config;
    const RouteConfig* active = &current_config;
    loop.config_ptr = &active;

    Connection idle;
    idle.reset();
    Http2Conn idle_h2;
    idle_h2.init_client();
    idle_h2.grpc.upstream = true;
    idle_h2.peer_settings_seen = true;
    idle.h2 = &idle_h2;
    idle.request_config = &current_config;
    idle.upstream_idx = 0;
    idle.upstream_backend_idx = 0;
    grpc_record_session_failure(&loop, idle, monotonic_us());
    CHECK_EQ(health->fails, 0u);

    Connection rejected;
    rejected.reset();
    Http2Conn rejected_h2;
    rejected_h2.init_client();
    rejected_h2.grpc.upstream = true;
    rejected_h2.peer_settings_seen = true;
    rejected.h2 = &rejected_h2;
    rejected.request_config = &current_config;
    rejected.upstream_idx = 0;
    rejected.upstream_backend_idx = 0;
    REQUIRE(rejected_h2.open_stream(3) != nullptr);
    rejected_h2.peer_goaway = true;
    rejected_h2.peer_last_stream = 1;
    GrpcExchange rejected_exchange;
    rejected_exchange.init();
    rejected_exchange.upstream = &rejected;
    rejected_exchange.upstream_stream = 3;
    rejected_exchange.request_headers_sent = true;
    REQUIRE(grpc_attach(rejected_h2, &rejected_exchange));
    grpc_record_session_failure(&loop, rejected, monotonic_us());
    CHECK_EQ(health->fails, 0u);

    Connection stale;
    stale.reset();
    Http2Conn stale_h2;
    stale_h2.init_client();
    stale_h2.grpc.upstream = true;
    stale_h2.peer_settings_seen = true;
    stale.h2 = &stale_h2;
    stale.request_config = &stale_config;
    stale.upstream_idx = 0;
    stale.upstream_backend_idx = 0;
    REQUIRE(stale_h2.open_stream(1) != nullptr);
    GrpcExchange stale_exchange;
    stale_exchange.init();
    stale_exchange.upstream = &stale;
    stale_exchange.upstream_stream = 1;
    stale_exchange.request_headers_sent = true;
    REQUIRE(grpc_attach(stale_h2, &stale_exchange));
    grpc_record_session_failure(&loop, stale, monotonic_us());
    CHECK_EQ(health->fails, 0u);
}
TEST(grpc_proxy, header_ended_positive_content_length_stays_local_failure) {
    EpollEventLoop loop;
    REQUIRE(loop.init(0, -1).has_value());
    RouteConfig cfg;
    REQUIRE(cfg.add_upstream("grpc", 0x7f000001, 1).has_value());
    cfg.upstreams[0].http2 = true;
    Connection* down = loop.alloc_conn();
    REQUIRE(down != nullptr);
    REQUIRE(loop.alloc_h2(*down));
    down->h2->init_client();
    down->h2->open_stream(1);
    down->request_config = &cfg;
    ParsedRequest req;
    req.reset();
    req.method = HttpMethod::POST;
    req.headers[0] = {Str{"content-type", 12}, Str{"application/grpc", 16}};
    req.header_count = 1;
    req.has_content_length = true;
    req.content_length = 5;
    req.content_length_count = 1;
    const hpack::Header hs[] = {{{":method", 7}, {"POST", 4}},
                                {{":scheme", 7}, {"http", 4}},
                                {{":path", 5}, {"/Echo", 5}},
                                {{":authority", 10}, {"x", 1}},
                                {{"content-type", 12}, {"application/grpc", 16}}};
    REQUIRE(grpc_start_impl(&loop, *down, 1, &cfg, 0, hs, 5, req, true));
    CHECK_EQ(down->h2->grpc.active, 0u);
    CHECK_GT(down->send_buf.len(), 0u);
    CHECK(loop.grpc_upstreams == nullptr);
    loop.force_close_all();
    loop.shutdown();
}
TEST(grpc_proxy, h2_web_expect_with_body_is_rejected_before_upstream) {
    struct Case {
        Str content_type;
        Str expect_name;
        Str expect_value;
    };
    const Case cases[] = {
        {lit_str("application/grpc-web"), lit_str("ExPeCt"), lit_str(" \t100-continue\t ")},
        {lit_str("application/grpc-web-text"), lit_str("expect"), lit_str("100-continue")},
    };
    for (const auto& test_case : cases) {
        EpollEventLoop loop;
        REQUIRE(loop.init(0, -1).has_value());
        RouteConfig cfg;
        REQUIRE(cfg.add_upstream("grpc", 0x7f000001, 1).has_value());
        cfg.upstreams[0].http2 = true;
        Connection* down = loop.alloc_conn();
        REQUIRE(down != nullptr);
        REQUIRE(loop.alloc_h2(*down));
        down->h2->init_client();
        REQUIRE(down->h2->open_stream(1));
        down->request_config = &cfg;
        ParsedRequest req;
        req.reset();
        req.method = HttpMethod::POST;
        req.headers[0] = {lit_str("content-type"), test_case.content_type};
        req.header_count = 1;
        req.has_content_length = true;
        req.content_length = 5;
        req.content_length_count = 1;
        const hpack::Header hs[] = {{{":method", 7}, {"POST", 4}},
                                    {{":scheme", 7}, {"http", 4}},
                                    {{":path", 5}, {"/Echo", 5}},
                                    {{":authority", 10}, {"x", 1}},
                                    {{"content-type", 12}, test_case.content_type},
                                    {test_case.expect_name, test_case.expect_value}};
        CHECK_FALSE(grpc_start_impl(&loop, *down, 1, &cfg, 0, hs, 6, req, false));
        CHECK_EQ(down->h2->grpc.active, 0u);
        CHECK(down->h2->grpc.streams[0] == nullptr);
        CHECK(loop.grpc_upstreams == nullptr);
        CHECK_EQ(down->send_buf.len(), 0u);
        loop.force_close_all();
        loop.shutdown();
    }
}

TEST(grpc_proxy, h2_web_bodiless_expect_remains_admitted) {
    EpollEventLoop loop;
    REQUIRE(loop.init(0, -1).has_value());
    RouteConfig cfg;
    REQUIRE(cfg.add_upstream("grpc", 0x7f000001, 1).has_value());
    cfg.upstreams[0].http2 = true;
    Connection* down = loop.alloc_conn();
    REQUIRE(down != nullptr);
    REQUIRE(loop.alloc_h2(*down));
    down->h2->init_client();
    REQUIRE(down->h2->open_stream(1));
    down->request_config = &cfg;
    ParsedRequest req;
    req.reset();
    req.method = HttpMethod::POST;
    req.headers[0] = {lit_str("content-type"), lit_str("application/grpc-web")};
    req.header_count = 1;
    req.has_content_length = true;
    req.content_length = 0;
    req.content_length_count = 1;
    const hpack::Header hs[] = {{{":method", 7}, {"POST", 4}},
                                {{":scheme", 7}, {"http", 4}},
                                {{":path", 5}, {"/Echo", 5}},
                                {{":authority", 10}, {"x", 1}},
                                {{"content-type", 12}, {"application/grpc-web", 20}},
                                {{"expect", 6}, {"100-continue", 12}}};
    CHECK(grpc_start_impl(&loop, *down, 1, &cfg, 0, hs, 6, req, true));
    loop.force_close_all();
    loop.shutdown();
}

TEST(grpc_proxy, h2_duplicate_web_family_content_types_rejected_before_upstream) {
    EpollEventLoop loop;
    REQUIRE(loop.init(0, -1).has_value());
    RouteConfig cfg;
    REQUIRE(cfg.add_upstream("grpc", 0x7f000001, 1).has_value());
    cfg.upstreams[0].http2 = true;
    Connection* down = loop.alloc_conn();
    REQUIRE(down != nullptr);
    REQUIRE(loop.alloc_h2(*down));
    down->h2->init_client();
    REQUIRE(down->h2->open_stream(1));
    down->request_config = &cfg;
    ParsedRequest req;
    req.reset();
    req.method = HttpMethod::POST;
    req.headers[0] = {lit_str("content-type"), lit_str("application/grpc-web+json")};
    req.headers[1] = {lit_str("content-type"), lit_str("application/grpc")};
    req.header_count = 2;
    const hpack::Header hs[] = {{{":method", 7}, {"POST", 4}},
                                {{":scheme", 7}, {"http", 4}},
                                {{":path", 5}, {"/Echo", 5}},
                                {{":authority", 10}, {"x", 1}},
                                {{"content-type", 12}, {"application/grpc-web+json", 25}},
                                {{"content-type", 12}, {"application/grpc", 16}}};
    CHECK_FALSE(grpc_start_impl(&loop, *down, 1, &cfg, 0, hs, 6, req, true));
    CHECK_EQ(down->h2->grpc.active, 0u);
    CHECK(down->h2->grpc.streams[0] == nullptr);
    CHECK(loop.grpc_upstreams == nullptr);
    loop.force_close_all();
    loop.shutdown();
}
TEST(grpc_proxy, grpc_response_mutations_snapshot_per_exchange) {
    Connection downstream;
    downstream.reset();
    GrpcExchange first;
    first.init();
    downstream.resp_header_mutations[0] = {
        {"x-first", 7}, {"one", 3}, Connection::RespHeaderMutationMode::Set};
    downstream.resp_header_mutations[1] = {
        {"x-remove", 8}, {nullptr, 0}, Connection::RespHeaderMutationMode::Remove};
    downstream.resp_header_mutation_count = 2;
    REQUIRE(grpc_snapshot_response_mutations(downstream, first));
    downstream.resp_header_mutations[0] = {
        {"x-first", 7}, {"two", 3}, Connection::RespHeaderMutationMode::Set};
    GrpcExchange second;
    second.init();
    REQUIRE(grpc_snapshot_response_mutations(downstream, second));

    hpack::Header headers[4] = {
        {{"x-first", 7}, {"upstream", 8}},
        {{"x-remove", 8}, {"gone", 4}},
        {{"content-type", 12}, {"application/grpc", 16}},
        {{"grpc-status", 11}, {"0", 1}},
    };
    u32 count = 4;
    REQUIRE(grpc_apply_response_mutations(first, headers, &count, 8));
    CHECK_EQ(count, 3u);
    CHECK(headers[0].name.eq({"content-type", 12}));
    CHECK(headers[1].name.eq({"grpc-status", 11}));
    CHECK(headers[2].name.eq({"x-first", 7}));
    CHECK(headers[2].value.eq({"one", 3}));
    count = 4;
    headers[0].value = {"upstream", 8};
    headers[1].value = {"gone", 4};
    REQUIRE(grpc_apply_response_mutations(second, headers, &count, 8));
    CHECK_EQ(count, 3u);
    CHECK(headers[2].value.eq({"two", 3}));

    u8 oversized_name[GrpcExchange::kHeaders]{};
    downstream.resp_header_mutations[0].name = {reinterpret_cast<const char*>(oversized_name),
                                                GrpcExchange::kHeaders};
    downstream.resp_header_mutation_count = 1;
    first.init();
    CHECK_FALSE(grpc_snapshot_response_mutations(downstream, first));
    CHECK(first.response_mutation_overflow);
}

TEST(grpc_proxy, grpc_web_response_mutations_survive_content_type_rewrite) {
    GrpcDriveFixture loop;
    Connection upstream, downstream;
    upstream.reset();
    downstream.reset();
    Http2Conn upstream_h2, downstream_h2;
    upstream_h2.init_client();
    upstream_h2.grpc.upstream = true;
    downstream_h2.init_client();
    upstream.h2 = &upstream_h2;
    downstream.h2 = &downstream_h2;
    REQUIRE(upstream_h2.open_stream(1));
    REQUIRE(downstream_h2.open_stream(1));
    GrpcExchange x;
    x.init();
    x.web_mode = GrpcWebContentType::Binary;
    x.upstream = &upstream;
    x.downstream = &downstream;
    x.upstream_stream = x.downstream_stream = 1;
    downstream.resp_header_mutations[0] = {{"access-control-allow-origin", 27},
                                           {"https://example.test", 20},
                                           Connection::RespHeaderMutationMode::Set};
    downstream.resp_header_mutation_count = 1;
    REQUIRE(grpc_snapshot_response_mutations(downstream, x));
    REQUIRE(grpc_attach(upstream_h2, &x));
    REQUIRE(grpc_attach(downstream_h2, &x));
    const hpack::Header headers[] = {{{":status", 7}, {"200", 3}},
                                     {{"content-type", 12}, {"application/grpc", 16}}};
    GrpcClientDispatch<GrpcDriveFixture> dispatch{&loop, &upstream};
    grpc_response_headers<GrpcDriveFixture>(&dispatch, upstream_h2, 1, headers, 2, false);
    CHECK_GT(x.response_headers_len, 9u);
    if (x.response_headers_len > 9) {
        hpack::DynamicTable dynamic;
        dynamic.init(0);
        u8 decoded_storage[1024];
        hpack::Header decoded[8];
        u32 decoded_count = 0;
        const u32 block_len = x.response_headers_len - 9;
        CHECK(hpack::decode_header_block(dynamic,
                                         x.response_headers + 9,
                                         block_len,
                                         decoded_storage,
                                         sizeof(decoded_storage),
                                         decoded,
                                         8,
                                         &decoded_count));
        bool web_type = false, cors = false;
        for (u32 i = 0; i < decoded_count; i++) {
            if (decoded[i].name.eq({"content-type", 12}))
                web_type = decoded[i].value.eq({"application/grpc-web", 20});
            if (decoded[i].name.eq({"access-control-allow-origin", 27}))
                cors = decoded[i].value.eq({"https://example.test", 20});
        }
        CHECK(web_type);
        CHECK(cors);
    }
}

TEST(grpc_proxy, grpc_web_backend_content_type_admission_is_order_independent) {
    auto run =
        [&](GrpcWebContentType mode, const hpack::Header* headers, u32 count, bool expect_failure) {
            GrpcDriveFixture loop;
            Connection upstream, downstream;
            upstream.reset();
            downstream.reset();
            Http2Conn upstream_h2, downstream_h2;
            upstream_h2.init_client();
            upstream_h2.grpc.upstream = true;
            downstream_h2.init_client();
            upstream.h2 = &upstream_h2;
            downstream.h2 = &downstream_h2;
            REQUIRE(upstream_h2.open_stream(1) != nullptr);
            REQUIRE(downstream_h2.open_stream(1) != nullptr);
            GrpcExchange x;
            x.init();
            x.web_mode = mode;
            x.upstream = &upstream;
            x.downstream = &downstream;
            x.upstream_stream = x.downstream_stream = 1;
            REQUIRE(grpc_attach(upstream_h2, &x));
            REQUIRE(grpc_attach(downstream_h2, &x));
            GrpcClientDispatch<GrpcDriveFixture> dispatch{&loop, &upstream};
            grpc_response_headers<GrpcDriveFixture>(
                &dispatch, upstream_h2, 1, headers, count, false);
            CHECK_EQ(x.failure != 0, expect_failure);
            if (expect_failure) {
                CHECK_EQ(x.failure, 13u);
                CHECK(x.response_end);
            } else {
                CHECK(x.response_headers_len > 9);
                CHECK(x.upstream == &upstream);
            }
            grpc_detach(downstream_h2, &x);
        };

    const hpack::Header json[] = {{{":status", 7}, {"200", 3}},
                                  {{"content-type", 12}, {"application/grpc+json", 21}}};
    run(GrpcWebContentType::Binary, json, 2, true);

    const hpack::Header json_then_proto[] = {
        {{":status", 7}, {"200", 3}},
        {{"content-type", 12}, {"application/grpc+json", 21}},
        {{"content-type", 12}, {"application/grpc+proto", 22}},
    };
    const hpack::Header proto_then_json[] = {
        {{":status", 7}, {"200", 3}},
        {{"content-type", 12}, {"application/grpc+proto", 22}},
        {{"content-type", 12}, {"application/grpc+json", 21}},
    };
    run(GrpcWebContentType::Binary, json_then_proto, 3, true);
    run(GrpcWebContentType::Binary, proto_then_json, 3, true);
    run(GrpcWebContentType::Native, json, 2, false);
}

TEST(grpc_proxy, grpc_web_incomplete_unstaged_message_becomes_status_trailer) {
    GrpcDriveFixture loop;
    Connection upstream, downstream;
    upstream.reset();
    downstream.reset();
    Http2Conn upstream_h2, downstream_h2;
    upstream_h2.init_client();
    upstream_h2.grpc.upstream = true;
    downstream_h2.init_client();
    upstream.h2 = &upstream_h2;
    downstream.h2 = &downstream_h2;
    REQUIRE(upstream_h2.open_stream(1));
    REQUIRE(downstream_h2.open_stream(1));
    GrpcExchange x;
    x.init();
    x.web_mode = GrpcWebContentType::Binary;
    x.upstream = &upstream;
    x.downstream = &downstream;
    x.upstream_stream = x.downstream_stream = 1;
    x.response_headers_sent = true;
    x.response_message.init(0xffffffffu);
    REQUIRE(grpc_attach(upstream_h2, &x));
    REQUIRE(grpc_attach(downstream_h2, &x));
    GrpcClientDispatch<GrpcDriveFixture> dispatch{&loop, &upstream};
    const u8 partial[] = {0, 0, 0, 0, 4, 0xaa, 0xbb};
    grpc_response_data<GrpcDriveFixture>(&dispatch, upstream_h2, 1, partial, sizeof(partial), true);
    CHECK_EQ(x.failure, 13u);
    CHECK(!x.web_response_invalid);
    CHECK(x.response_end);
    CHECK_EQ(x.download_len, 0u);
    CHECK_EQ(grpc_web_prepare_failure(x), 0u);
    CHECK(x.web_failure_prepared);
    CHECK(x.web_trailer_queued);
    GrpcExchange expected;
    expected.init();
    REQUIRE(grpc_web_queue_status_trailer(expected, 13));
    CHECK_EQ(x.response_trailers_len, expected.response_trailers_len);
    CHECK_EQ(memcmp(x.response_trailers, expected.response_trailers, x.response_trailers_len), 0);
}

TEST(grpc_proxy, grpc_web_removed_trailers_only_status_becomes_unknown_trailer) {
    GrpcDriveFixture loop;
    ShardMetrics metrics{};
    loop.metrics = &metrics;
    Connection upstream, downstream;
    upstream.reset();
    downstream.reset();
    Http2Conn upstream_h2, downstream_h2;
    upstream_h2.init_client();
    upstream_h2.grpc.upstream = true;
    downstream_h2.init_client();
    upstream.h2 = &upstream_h2;
    downstream.h2 = &downstream_h2;
    REQUIRE(upstream_h2.open_stream(1));
    REQUIRE(downstream_h2.open_stream(1));
    auto* x = reinterpret_cast<GrpcExchange*>(loop.pool.alloc_bulk());
    REQUIRE(x != nullptr);
    x->init();
    x->web_mode = GrpcWebContentType::Binary;
    x->upstream = &upstream;
    x->downstream = &downstream;
    x->upstream_stream = x->downstream_stream = 1;
    x->started_us = monotonic_us();
    x->observed = true;
    metrics.on_grpc_start();
    downstream.resp_header_mutations[0] = {
        {"grpc-status", 11}, {nullptr, 0}, Connection::RespHeaderMutationMode::Remove};
    downstream.resp_header_mutation_count = 1;
    REQUIRE(grpc_snapshot_response_mutations(downstream, *x));
    REQUIRE(grpc_attach(upstream_h2, x));
    REQUIRE(grpc_attach(downstream_h2, x));
    GrpcClientDispatch<GrpcDriveFixture> dispatch{&loop, &upstream};
    const hpack::Header response[] = {
        {{":status", 7}, {"200", 3}},
        {{"content-type", 12}, {"application/grpc", 16}},
        {{"grpc-status", 11}, {"0", 1}},
    };
    grpc_response_headers<GrpcDriveFixture>(&dispatch, upstream_h2, 1, response, 3, true);
    CHECK_EQ(x->failure, 2u);
    CHECK_EQ(x->response_status, 2u);
    CHECK(x->response_end);
    CHECK_EQ(metrics.grpc_active, 1u);

    CHECK_EQ(grpc_web_prepare_failure(*x), 0u);
    CHECK(x->web_trailer_queued);
    GrpcExchange expected;
    expected.init();
    REQUIRE(grpc_web_queue_status_trailer(expected, 2));
    CHECK_EQ(x->response_trailers_len, expected.response_trailers_len);
    CHECK_EQ(memcmp(x->response_trailers, expected.response_trailers, x->response_trailers_len), 0);

    x->response_end_sent = true;
    grpc_observe(&loop, *x);
    CHECK_EQ(metrics.grpc_completed[2], 1u);
    CHECK_EQ(metrics.grpc_active, 0u);
    grpc_observe(&loop, *x);
    CHECK_EQ(metrics.grpc_completed[2], 1u);
    loop.pool.free(reinterpret_cast<u8*>(x));
}

TEST(grpc_proxy, grpc_web_text_batches_independently_padded_messages) {
    GrpcDriveFixture loop;
    Connection downstream;
    downstream.reset();
    Http2Conn h;
    h.init_client();
    downstream.h2 = &h;
    REQUIRE(h.open_stream(1) != nullptr);
    GrpcExchange x;
    x.init();
    x.web_mode = GrpcWebContentType::Text;
    x.downstream = &downstream;
    x.downstream_stream = 1;
    x.response_headers_sent = true;
    REQUIRE(grpc_attach(h, &x));
    constexpr u32 messages = 128;
    constexpr u32 native_size = 7;
    for (u32 j = 0; j < messages; j++) {
        const u8 message[] = {0, 0, 0, 0, 2, static_cast<u8>(j), 0xaa};
        memcpy(x.download + j * native_size, message, sizeof(message));
    }
    x.download_len = messages * native_size;
    u8 expected[messages * native_size];
    memcpy(expected, x.download, sizeof(expected));
    u8 output[kDefaultMaxFrameSize + kFrameHeaderSize];
    const u32 n = grpc_pump_downstream(&loop, downstream, output, sizeof(output));
    Http2FrameHeader frame;
    REQUIRE(parse_frame_header(output, n, &frame) == ParseStatus::Complete);
    CHECK_EQ(frame.type, static_cast<u8>(Http2FrameType::Data));
    CHECK_EQ(frame.length, messages * 12u);
    CHECK_EQ(n, kFrameHeaderSize + frame.length);
    CHECK_EQ(x.download_len, 0u);
    CHECK_EQ(x.response_base64.pending_len, 0u);
    u8 decoded[sizeof(expected)];
    GrpcWebBase64Decoder decoder;
    decoder.init();
    u32 consumed = 0, written = 0;
    CHECK_EQ(
        decoder.feed(
            output + kFrameHeaderSize, frame.length, consumed, decoded, sizeof(decoded), written),
        GrpcWebCodecStatus::Ok);
    CHECK_EQ(consumed, frame.length);
    CHECK_EQ(written, sizeof(expected));
    CHECK_EQ(decoder.finish(), GrpcWebCodecStatus::Ok);
    CHECK(memcmp(expected, decoded, sizeof(expected)) == 0);
    CHECK_EQ(x.staged_response_message.header_bytes, 0u);
    CHECK_EQ(x.staged_response_message.remaining, 0u);
    grpc_detach(h, &x);
}

TEST(grpc_proxy, grpc_web_h1_headers_fit_framing_at_exact_slice_capacity) {
    HeldSendGrpcDriveFixture loop;
    Connection conn;
    conn.reset();
    conn.fd = 41;
    u8 send_storage[SlicePool::kSliceSize];
    conn.send_buf.bind(send_storage, sizeof(send_storage));

    GrpcExchange x;
    x.init();
    x.web_mode = GrpcWebContentType::Binary;
    static constexpr char kName[] = "x";
    static constexpr u32 kMaxMetadata = GrpcExchange::kHeaders - 38;
    static constexpr u32 kContentTypeWire = 12 + 2 + 20 + 2;
    static constexpr u32 kLargeValueLen = kMaxMetadata - kContentTypeWire - 5;
    u8 large_value[kLargeValueLen + 1]{};
    hpack::Header exact[] = {
        {{"content-type", 12}, {"application/grpc", 16}},
        {{kName, 1}, {reinterpret_cast<const char*>(large_value), kLargeValueLen}}};
    REQUIRE(grpc_web_queue_h1_headers(x, exact, 2, false));
    CHECK_EQ(x.response_headers_len, kMaxMetadata);

    x.init();
    hpack::Header oversized[] = {
        {{"content-type", 12}, {"application/grpc", 16}},
        {{kName, 1}, {reinterpret_cast<const char*>(large_value), kLargeValueLen + 1}}};
    CHECK_FALSE(grpc_web_queue_h1_headers(x, oversized, 2, false));

    // The exact accepted metadata size plus the bridge framing occupies the
    // full downstream send slice without truncation.
    x.init();
    x.web_mode = GrpcWebContentType::Binary;
    REQUIRE(grpc_web_queue_h1_headers(x, exact, 2, false));
    grpc_web_h1_pump_response(&loop, conn, x);
    CHECK_EQ(loop.sends, 1u);
    CHECK_EQ(loop.pending_send_len, SlicePool::kSliceSize);
    CHECK_FALSE(loop.closed);
}

TEST(grpc_proxy, grpc_web_terminal_data_can_end_with_zero_flow_control_credit) {
    for (const auto mode : {GrpcWebContentType::Binary, GrpcWebContentType::Text}) {
        GrpcDriveFixture loop;
        Connection downstream;
        downstream.reset();
        Http2Conn h;
        h.init_client();
        downstream.h2 = &h;
        auto* stream = h.open_stream(1);
        REQUIRE(stream != nullptr);
        stream->send_window = 0;
        h.conn_send_window = 0;
        GrpcExchange x;
        x.init();
        x.web_mode = mode;
        x.downstream = &downstream;
        x.downstream_stream = 1;
        x.response_headers_sent = true;
        x.response_end = true;
        x.web_body_flushed = true;
        REQUIRE(grpc_attach(h, &x));

        u8 output[9];
        CHECK_EQ(grpc_pump_downstream(&loop, downstream, output, sizeof(output)), 9u);
        CHECK_EQ(output[3], static_cast<u8>(Http2FrameType::Data));
        CHECK_EQ(output[4], http2_flag::kEndStream);
        CHECK_EQ(output[0] | output[1] | output[2], 0u);
        CHECK_EQ(stream->send_window, 0);
        CHECK_EQ(h.conn_send_window, 0u);
    }

    GrpcDriveFixture loop;
    Connection downstream;
    downstream.reset();
    Http2Conn h;
    h.init_client();
    downstream.h2 = &h;
    auto* stream = h.open_stream(1);
    REQUIRE(stream != nullptr);
    stream->send_window = 0;
    h.conn_send_window = 0;
    GrpcExchange x;
    x.init();
    x.web_mode = GrpcWebContentType::Binary;
    x.downstream = &downstream;
    x.downstream_stream = 1;
    x.response_headers_sent = true;
    x.response_end = true;
    x.download[0] = 1;
    x.download_len = 1;
    REQUIRE(grpc_attach(h, &x));
    u8 output[9];
    CHECK_EQ(grpc_pump_downstream(&loop, downstream, output, sizeof(output)), 0u);
    CHECK_EQ(x.download_len, 1u);
}

TEST(grpc_proxy, native_trailer_emits_pending_hpack_resize_after_data_stall) {
    Http2Conn h;
    h.init_client();
    auto* stream = h.open_stream(1);
    REQUIRE(stream != nullptr);

    // Put the encoder and a peer decoder into a non-empty, synchronized state.
    u8 first[256];
    const hpack::Header first_headers[] = {{{"x-seed", 6}, {"value", 5}}};
    const u32 first_len = http2_write_response(
        first, sizeof(first), h.hpack_enc, 1, 200, first_headers, 1, nullptr, 0);
    REQUIRE_GT(first_len, 0u);
    hpack::DynamicTable decoder;
    decoder.init(kDefaultHeaderTableSize);
    hpack::Header decoded[8];
    u8 decoded_storage[256];
    u32 decoded_count = 0;
    REQUIRE(hpack::decode_header_block(decoder,
                                       first + kFrameHeaderSize,
                                       first_len - kFrameHeaderSize,
                                       decoded_storage,
                                       sizeof(decoded_storage),
                                       decoded,
                                       8,
                                       &decoded_count));

    static const u8 body[] = {0xaa, 0xbb};
    h.outbound_stream = 1;
    h.outbound_body = body;
    h.outbound_body_len = sizeof(body);
    h.outbound_body_offset = 0;
    h.outbound_grpc_status = 0;
    h.conn_send_window = 0;
    stream->send_window = 0;
    h.hpack_enc.set_table_size(0);
    CHECK_GE(h.hpack_enc.pending_size_update, 0);

    u8 output[128];
    H2PumpStatus status = H2PumpStatus::Blocked;
    CHECK_EQ(h2_pump_outbound(h, output, sizeof(output), status), 0u);
    CHECK_EQ(status, H2PumpStatus::Blocked);
    CHECK_GE(h.hpack_enc.pending_size_update, 0);

    h.conn_send_window = 16;
    stream->send_window = 16;
    REQUIRE_EQ(h2_pump_outbound(h, output, sizeof(output), status), 11u);
    CHECK_EQ(status, H2PumpStatus::Produced);
    CHECK_EQ(h.outbound_body_offset, sizeof(body));

    // A failed output attempt must leave the resize armed for the retry.
    CHECK_EQ(h2_pump_outbound(h, output, kFrameHeaderSize, status), 0u);
    CHECK_GE(h.hpack_enc.pending_size_update, 0);
    const u32 trailer_len = h2_pump_outbound(h, output, sizeof(output), status);
    REQUIRE_GT(trailer_len, static_cast<u32>(kFrameHeaderSize));
    CHECK_EQ(status, H2PumpStatus::Produced);
    Http2FrameHeader trailer_frame;
    REQUIRE(parse_frame_header(output, trailer_len, &trailer_frame) == ParseStatus::Complete);
    CHECK_EQ(trailer_frame.type, static_cast<u8>(Http2FrameType::Headers));
    REQUIRE(hpack::decode_header_block(decoder,
                                       output + kFrameHeaderSize,
                                       trailer_frame.length,
                                       decoded_storage,
                                       sizeof(decoded_storage),
                                       decoded,
                                       8,
                                       &decoded_count));
    REQUIRE_EQ(decoded_count, 1u);
    CHECK(decoded[0].name.eq({"grpc-status", 11}));
    CHECK(decoded[0].value.eq({"0", 1}));
    CHECK_EQ(h.hpack_enc.pending_size_update, -1);
}

TEST(grpc_proxy, grpc_web_text_large_message_batches_data_frames) {
    GrpcDriveFixture loop;
    Connection downstream;
    downstream.reset();
    Http2Conn h;
    h.init_client();
    downstream.h2 = &h;
    auto* stream = h.open_stream(1);
    REQUIRE(stream != nullptr);
    stream->send_window = 1 << 20;
    h.conn_send_window = 1 << 20;
    GrpcExchange x;
    x.init();
    x.web_mode = GrpcWebContentType::Text;
    x.downstream = &downstream;
    x.downstream_stream = 1;
    x.response_headers_sent = true;
    REQUIRE(grpc_attach(h, &x));
    constexpr u32 payload_size = 131072;
    constexpr u32 message_size = payload_size + 5;
    auto message = std::make_unique<u8[]>(message_size);
    auto decoded = std::make_unique<u8[]>(message_size);
    message[0] = 0;
    message[1] = static_cast<u8>(payload_size >> 24);
    message[2] = static_cast<u8>(payload_size >> 16);
    message[3] = static_cast<u8>(payload_size >> 8);
    message[4] = static_cast<u8>(payload_size);
    for (u32 j = 5; j < message_size; j++) message[j] = static_cast<u8>(j);
    GrpcWebBase64Decoder decoder;
    decoder.init();
    u32 supplied = 0, decoded_size = 0, frames = 0;
    u8 output[kDefaultMaxFrameSize + kFrameHeaderSize];
    for (u32 turn = 0; turn < 64; turn++) {
        if (!x.download_len && supplied < message_size) {
            u32 chunk = message_size - supplied;
            if (chunk > sizeof(x.download)) chunk = sizeof(x.download);
            memcpy(x.download, message.get() + supplied, chunk);
            x.download_len = chunk;
            supplied += chunk;
        }
        const u32 n = grpc_pump_downstream(&loop, downstream, output, sizeof(output));
        if (n) {
            frames++;
            Http2FrameHeader frame;
            REQUIRE(parse_frame_header(output, n, &frame) == ParseStatus::Complete);
            CHECK_EQ(frame.type, static_cast<u8>(Http2FrameType::Data));
            CHECK_EQ(n, kFrameHeaderSize + frame.length);
            CHECK_LE(frame.length, kDefaultMaxFrameSize);
            u32 consumed = 0, written = 0;
            CHECK_EQ(decoder.feed(output + kFrameHeaderSize,
                                  frame.length,
                                  consumed,
                                  decoded.get() + decoded_size,
                                  message_size - decoded_size,
                                  written),
                     GrpcWebCodecStatus::Ok);
            CHECK_EQ(consumed, frame.length);
            decoded_size += written;
        }
        if (supplied == message_size && !x.download_len && !x.response_base64.pending_len &&
            !x.web_encode_boundary_pending &&
            x.web_pending_output_offset == x.web_pending_output_len)
            break;
    }
    CHECK_EQ(supplied, message_size);
    CHECK_EQ(decoded_size, message_size);
    CHECK_EQ(decoder.finish(), GrpcWebCodecStatus::Ok);
    CHECK(memcmp(message.get(), decoded.get(), message_size) == 0);
    CHECK_LE(frames, 16u);
    CHECK_GT(frames, 1u);
    CHECK_EQ(x.staged_response_message.header_bytes, 0u);
    CHECK_EQ(x.staged_response_message.remaining, 0u);
    grpc_detach(h, &x);
}

TEST(grpc_proxy, grpc_web_reset_uses_downstream_staged_message_boundary) {
    auto run = [=](const u8* staged,
                   u32 staged_len,
                   u32 send_window,
                   GrpcWebContentType mode,
                   const u8* received,
                   u32 received_len,
                   Http2Error reset_error,
                   bool size_failure,
                   bool expect_invalid) {
        GrpcDriveFixture loop;
        Connection upstream, downstream;
        upstream.reset();
        downstream.reset();
        u8 upstream_recv[SlicePool::kSliceSize];
        upstream.bind_request_receive_buffer(upstream_recv, sizeof(upstream_recv));
        u8 downstream_send[SlicePool::kSliceSize];
        downstream.send_slice = downstream_send;
        downstream.send_buf.bind(downstream_send, sizeof(downstream_send));
        downstream.on_send = &pending_send;
        Http2Conn upstream_h2, downstream_h2;
        upstream_h2.init_client();
        upstream_h2.grpc.upstream = true;
        downstream_h2.init_client();
        upstream.h2 = &upstream_h2;
        downstream.h2 = &downstream_h2;
        auto* up_stream = upstream_h2.open_stream(1);
        auto* down_stream = downstream_h2.open_stream(1);
        REQUIRE(up_stream != nullptr);
        REQUIRE(down_stream != nullptr);
        down_stream->send_window = static_cast<i32>(send_window);
        GrpcExchange x;
        x.init();
        x.web_mode = mode;
        x.upstream = &upstream;
        x.downstream = &downstream;
        x.upstream_stream = x.downstream_stream = 1;
        x.response_headers_sent = true;
        x.response_headers_len = 0;
        if (staged_len) {
            memcpy(x.download, staged, staged_len);
            x.download_len = staged_len;
        }
        if (size_failure) x.response_message.init(2);
        REQUIRE(grpc_attach(upstream_h2, &x));
        REQUIRE(grpc_attach(downstream_h2, &x));
        u8 output[128];
        if (staged_len) {
            x.upstream = nullptr;
            const u32 staged_output =
                grpc_pump_downstream(&loop, downstream, output, sizeof(output));
            CHECK_GT(staged_output, 0u);
            for (u32 i = 0; mode == GrpcWebContentType::Text && i < 3 &&
                            (x.download_len || x.response_base64.pending_len == 3);
                 i++)
                (void)grpc_pump_downstream(&loop, downstream, output, sizeof(output));
            x.upstream = &upstream;
        }
        if (received_len) {
            memcpy(x.download + x.download_len, received, received_len);
            x.download_len += received_len;
            (void)x.response_message.feed(received, received_len, false);
        }
        up_stream->manual_window = true;
        up_stream->recv_unconsumed = x.download_len;
        const u32 expected_reset_credit = x.download_len;
        GrpcClientDispatch<GrpcDriveFixture> dispatch{&loop, &upstream};
        if (size_failure) {
            const u8 too_large[] = {0, 0, 0, 0, 3};
            grpc_response_data<GrpcDriveFixture>(&dispatch, upstream_h2, 1, too_large, 5, false);
            CHECK_EQ(x.failure, 8u);
        } else {
            grpc_response_reset<GrpcDriveFixture>(&dispatch, upstream_h2, 1, reset_error);
        }
        CHECK_EQ(x.web_response_invalid, expect_invalid);
        if (!size_failure) {
            CHECK_EQ(up_stream->recv_unconsumed, 0u);
            CHECK_EQ(upstream_h2.conn_recv_credit, expected_reset_credit);
        }
        if (expect_invalid && mode == GrpcWebContentType::Binary) {
            CHECK_EQ(x.download_len, staged_len > send_window ? staged_len - send_window : 0u);
        } else if (!expect_invalid) {
            CHECK_EQ(x.download_len, 0u);
        }
        const u32 output_len = grpc_pump_downstream(&loop, downstream, output, sizeof(output));
        CHECK_GT(output_len, 0u);
        if (output_len >= 9) {
            CHECK_EQ(output[3],
                     expect_invalid ? static_cast<u8>(Http2FrameType::RstStream)
                                    : static_cast<u8>(Http2FrameType::Data));
        }
        grpc_detach(downstream_h2, &x);
    };
    const u8 message[] = {0, 0, 0, 0, 4, 0xaa, 0xbb, 0xcc, 0xdd};
    run(message,
        sizeof(message),
        6,
        GrpcWebContentType::Binary,
        nullptr,
        0,
        Http2Error::Cancel,
        false,
        true);
    run(message,
        sizeof(message),
        1000,
        GrpcWebContentType::Binary,
        nullptr,
        0,
        Http2Error::Cancel,
        false,
        false);
    run(nullptr, 0, 65535, GrpcWebContentType::Binary, nullptr, 0, Http2Error::Cancel, true, false);
    run(nullptr,
        0,
        65535,
        GrpcWebContentType::Binary,
        message,
        7,
        Http2Error::Cancel,
        false,
        false);
    run(message,
        sizeof(message),
        2,
        GrpcWebContentType::Text,
        nullptr,
        0,
        Http2Error::Cancel,
        false,
        true);
    run(message,
        sizeof(message),
        1000,
        GrpcWebContentType::Text,
        nullptr,
        0,
        Http2Error::Cancel,
        false,
        false);
    const u8 next_message_partial[] = {0, 0, 0, 0, 3, 0x11, 0x22};
    run(message,
        sizeof(message),
        1000,
        GrpcWebContentType::Binary,
        next_message_partial,
        sizeof(next_message_partial),
        Http2Error::Cancel,
        false,
        false);
    run(message,
        sizeof(message),
        1000,
        GrpcWebContentType::Text,
        next_message_partial,
        sizeof(next_message_partial),
        Http2Error::Cancel,
        false,
        false);
}

TEST(grpc_proxy, grpc_web_local_failure_trailer_survives_tiny_windows) {
    auto run = [&](bool backend_trailer_queued) {
        GrpcDriveFixture loop;
        Connection downstream;
        downstream.reset();
        Http2Conn downstream_h2;
        downstream_h2.init_client();
        downstream.h2 = &downstream_h2;
        auto* stream = downstream_h2.open_stream(1);
        REQUIRE(stream != nullptr);

        GrpcExchange x;
        x.init();
        x.web_mode = GrpcWebContentType::Text;
        x.downstream = &downstream;
        x.downstream_stream = 1;
        x.response_headers_sent = true;
        if (backend_trailer_queued) REQUIRE(grpc_web_queue_status_trailer(x, 0));
        x.failure = 4;
        REQUIRE(grpc_attach(downstream_h2, &x));

        GrpcExchange expected;
        expected.init();
        REQUIRE(grpc_web_queue_status_trailer(expected, x.failure));

        GrpcWebBase64Decoder decoder;
        decoder.init();
        u8 decoded[256];
        u32 decoded_len = 0;
        u8 output[64];
        bool ended = false;
        for (u32 i = 0; i < 256 && !ended; i++) {
            stream->send_window = 1;
            downstream_h2.conn_send_window = 1;
            const u32 output_len = grpc_pump_downstream(&loop, downstream, output, sizeof(output));
            REQUIRE_GT(output_len, 0u);
            CHECK_EQ(output[3], static_cast<u8>(Http2FrameType::Data));
            const u32 payload_len = (static_cast<u32>(output[0]) << 16) |
                                    (static_cast<u32>(output[1]) << 8) | output[2];
            CHECK_LE(payload_len, 1u);
            u32 consumed = 0, written = 0;
            REQUIRE_EQ(decoder.feed(output + 9,
                                    payload_len,
                                    consumed,
                                    decoded + decoded_len,
                                    sizeof(decoded) - decoded_len,
                                    written),
                       GrpcWebCodecStatus::Ok);
            CHECK_EQ(consumed, payload_len);
            decoded_len += written;
            ended = (output[4] & 1) != 0;
            CHECK(x.web_failure_prepared);
        }
        CHECK(ended);
        CHECK_EQ(decoder.finish(), GrpcWebCodecStatus::Ok);
        CHECK_EQ(decoded_len, expected.response_trailers_len);
        CHECK_EQ(memcmp(decoded, expected.response_trailers, decoded_len), 0);
        CHECK_EQ(x.staged_response_message.header_bytes, 0u);
        CHECK_EQ(x.staged_response_message.remaining, 0u);
        grpc_detach(downstream_h2, &x);
    };
    run(false);
    run(true);
}

TEST(grpc_proxy, grpc_web_text_flushes_each_open_stream_message) {
    auto check_message = [&](u32 payload_len, bool append_next_prefix) {
        GrpcDriveFixture loop;
        Connection downstream;
        downstream.reset();
        Http2Conn downstream_h2;
        downstream_h2.init_client();
        downstream.h2 = &downstream_h2;
        auto* stream = downstream_h2.open_stream(1);
        REQUIRE(stream != nullptr);

        GrpcExchange x;
        x.init();
        x.web_mode = GrpcWebContentType::Text;
        x.downstream = &downstream;
        x.downstream_stream = 1;
        x.response_headers_sent = true;
        u8 message[] = {0, 0, 0, 0, 0, 0xaa, 0xbb, 0xcc};
        message[4] = static_cast<u8>(payload_len);
        const u32 message_len = 5 + payload_len;
        memcpy(x.download, message, message_len);
        x.download_len = message_len;
        if (append_next_prefix) x.download[x.download_len++] = 0;
        REQUIRE(grpc_attach(downstream_h2, &x));

        GrpcWebBase64Decoder decoder;
        decoder.init();
        u8 decoded[64];
        u32 decoded_len = 0;
        u8 output[64];
        bool staged = false;
        for (u32 i = 0; i < 32 && !staged; i++) {
            const u32 output_len = grpc_pump_downstream(&loop, downstream, output, sizeof(output));
            if (output_len) {
                REQUIRE_EQ(output[3], static_cast<u8>(Http2FrameType::Data));
                const u32 payload_bytes = (static_cast<u32>(output[0]) << 16) |
                                          (static_cast<u32>(output[1]) << 8) | output[2];
                u32 consumed = 0, written = 0;
                REQUIRE_EQ(decoder.feed(output + 9,
                                        payload_bytes,
                                        consumed,
                                        decoded + decoded_len,
                                        sizeof(decoded) - decoded_len,
                                        written),
                           GrpcWebCodecStatus::Ok);
                REQUIRE_EQ(consumed, payload_bytes);
                decoded_len += written;
            }
            staged = decoded_len == message_len && !x.staged_response_message.header_bytes &&
                     !x.staged_response_message.remaining;
        }
        CHECK(staged);
        CHECK_EQ(decoded_len, message_len);
        CHECK_EQ(memcmp(decoded, message, message_len), 0);
        CHECK_EQ(decoder.finish(), GrpcWebCodecStatus::Ok);
        CHECK_EQ(x.download_len + x.response_base64.pending_len, append_next_prefix ? 1u : 0u);
        grpc_detach(downstream_h2, &x);
    };

    check_message(0, false);
    check_message(1, false);
    check_message(2, false);
    check_message(3, false);
    check_message(2, true);
}

TEST(grpc_proxy, grpc_web_local_failure_after_partial_trailer_resets) {
    GrpcDriveFixture loop;
    Connection downstream;
    downstream.reset();
    Http2Conn downstream_h2;
    downstream_h2.init_client();
    downstream.h2 = &downstream_h2;
    auto* stream = downstream_h2.open_stream(1);
    REQUIRE(stream != nullptr);

    GrpcExchange x;
    x.init();
    x.web_mode = GrpcWebContentType::Text;
    x.downstream = &downstream;
    x.downstream_stream = 1;
    x.response_headers_sent = true;
    x.response_end = true;
    REQUIRE(grpc_web_queue_status_trailer(x, 0));
    REQUIRE(grpc_attach(downstream_h2, &x));

    stream->send_window = 1;
    downstream_h2.conn_send_window = 1;
    u8 output[64];
    const u32 first_len = grpc_pump_downstream(&loop, downstream, output, sizeof(output));
    REQUIRE_GT(first_len, 0u);
    CHECK_EQ(output[3], static_cast<u8>(Http2FrameType::Data));
    CHECK_EQ((static_cast<u32>(output[0]) << 16) | (static_cast<u32>(output[1]) << 8) | output[2],
             1u);
    CHECK(x.web_trailer_wire_started);

    x.failure = 4;
    stream->send_window = 1;
    downstream_h2.conn_send_window = 1;
    const u32 reset_len = grpc_pump_downstream(&loop, downstream, output, sizeof(output));
    REQUIRE_GT(reset_len, 0u);
    CHECK(x.web_response_invalid);
    CHECK_EQ(output[3], static_cast<u8>(Http2FrameType::RstStream));
    grpc_detach(downstream_h2, &x);
}

TEST(grpc_proxy, grpc_web_upstream_reset_after_partial_trailer_resets_downstream) {
    for (const auto mode : {GrpcWebContentType::Binary, GrpcWebContentType::Text}) {
        GrpcDriveFixture loop;
        Connection upstream, downstream;
        upstream.reset();
        downstream.reset();
        u8 downstream_send[SlicePool::kSliceSize];
        downstream.send_slice = downstream_send;
        downstream.send_buf.bind(downstream_send, sizeof(downstream_send));
        downstream.on_send = &pending_send;
        Http2Conn upstream_h2, downstream_h2;
        upstream_h2.init_client();
        upstream_h2.grpc.upstream = true;
        downstream_h2.init_client();
        upstream.h2 = &upstream_h2;
        downstream.h2 = &downstream_h2;
        auto* up_stream = upstream_h2.open_stream(1);
        auto* down_stream = downstream_h2.open_stream(1);
        REQUIRE(up_stream != nullptr);
        REQUIRE(down_stream != nullptr);
        up_stream->manual_window = true;
        down_stream->send_window = 1;

        GrpcExchange x;
        x.init();
        x.web_mode = mode;
        x.upstream = &upstream;
        x.downstream = &downstream;
        x.upstream_stream = x.downstream_stream = 1;
        x.response_headers_sent = true;
        REQUIRE(grpc_web_queue_status_trailer(x, 0));
        REQUIRE(grpc_attach(upstream_h2, &x));
        REQUIRE(grpc_attach(downstream_h2, &x));

        u8 output[64];
        downstream_h2.conn_send_window = 1;
        Connection* upstream_connection = x.upstream;
        x.upstream = nullptr;
        const u32 first_len = grpc_pump_downstream(&loop, downstream, output, sizeof(output));
        x.upstream = upstream_connection;
        REQUIRE_GT(first_len, 0u);
        CHECK(x.web_trailer_wire_started);

        GrpcClientDispatch<GrpcDriveFixture> dispatch{&loop, &upstream};
        x.downstream = nullptr;
        upstream_h2.grpc.busy = true;
        grpc_response_reset<GrpcDriveFixture>(&dispatch, upstream_h2, 1, Http2Error::Cancel);
        upstream_h2.grpc.busy = false;
        x.downstream = &downstream;
        CHECK(x.web_response_invalid);
        CHECK(x.web_failure_prepared);
        CHECK_EQ(x.web_trailer_queued, true);
        down_stream->send_window = 16;
        downstream_h2.conn_send_window = 16;
        const u32 reset_len = grpc_pump_downstream(&loop, downstream, output, sizeof(output));
        REQUIRE_GT(reset_len, 0u);
        CHECK_EQ(output[3], static_cast<u8>(Http2FrameType::RstStream));
        grpc_detach(downstream_h2, &x);
    }
}

TEST(grpc_proxy, grpc_web_message_limit_applies_after_text_decode) {
    for (const bool text : {false, true}) {
        GrpcDriveFixture loop;
        Connection upstream, downstream;
        upstream.reset();
        downstream.reset();
        Http2Conn upstream_h2, downstream_h2;
        upstream_h2.init_client();
        upstream_h2.grpc.upstream = true;
        downstream_h2.init_client();
        upstream.h2 = &upstream_h2;
        downstream.h2 = &downstream_h2;
        REQUIRE(upstream_h2.open_stream(1));
        REQUIRE(downstream_h2.open_stream(1));
        GrpcExchange x;
        x.init();
        x.web_mode = text ? GrpcWebContentType::Text : GrpcWebContentType::Binary;
        x.upstream = &upstream;
        x.downstream = &downstream;
        x.upstream_stream = x.downstream_stream = 1;
        x.request_headers_sent = true;
        x.request_message.init(2);
        REQUIRE(grpc_attach(upstream_h2, &x));
        REQUIRE(grpc_attach(downstream_h2, &x));
        const u8 binary[] = {0, 0, 0, 0, 3, 0xaa, 0xbb, 0xcc};
        const u8 base64[] = {'A', 'A', 'A', 'A', 'A', 'A', 'O', 'q', 'u', '8', 'w', '='};
        const u8* input = text ? base64 : binary;
        const u32 input_len = text ? sizeof(base64) : sizeof(binary);
        grpc_request_data(&loop, downstream, x, input, input_len, true);
        CHECK_EQ(x.failure, 8u);
        CHECK(x.upstream == nullptr);
        CHECK_EQ(x.upload_len, 0u);
    }
}

TEST(grpc_proxy, expired_headers_deadline_is_cancelled_before_upstream_headers) {
    EpollEventLoop loop;
    REQUIRE(loop.init(0, -1).has_value());
    RouteConfig cfg;
    REQUIRE(cfg.add_upstream("grpc", 0x7f000001, 1).has_value());
    cfg.upstreams[0].http2 = true;
    Connection* down = loop.alloc_conn();
    REQUIRE(down != nullptr);
    REQUIRE(loop.alloc_h2(*down));
    down->h2->init_client();
    down->request_config = &cfg;
    auto* down_stream = down->h2->open_stream(1);
    REQUIRE(down_stream != nullptr);
    down_stream->headers_received_us = monotonic_us() - 1000;
    ParsedRequest req;
    req.reset();
    req.method = HttpMethod::POST;
    req.headers[0] = {Str{"content-type", 12}, Str{"application/grpc", 16}};
    req.header_count = 1;
    const hpack::Header hs[] = {{{":method", 7}, {"POST", 4}},
                                {{":scheme", 7}, {"http", 4}},
                                {{":path", 5}, {"/Echo", 5}},
                                {{":authority", 10}, {"x", 1}},
                                {{"grpc-timeout", 12}, {"1u", 2}},
                                {{"content-type", 12}, {"application/grpc", 16}}};
    REQUIRE(grpc_start_impl(&loop, *down, 1, &cfg, 0, hs, 6, req, true));
    CHECK_EQ(down->h2->grpc.active, 0u);
    CHECK(down->h2->grpc.streams[0] == nullptr);
    CHECK(loop.grpc_upstreams == nullptr);
    CHECK(down->send_buf.len() > 0);
    loop.force_close_all();
    loop.shutdown();
}
TEST(grpc_proxy, io_uring_tls_h2_bulk_input_is_bounded_and_released) {
    IoUringEventLoop loop;
    auto initialized = loop.init(0, -1);
    if (!initialized.has_value()) SKIP("io_uring unavailable");
    Connection* conn = loop.alloc_conn();
    REQUIRE(conn != nullptr);
    void* region = mmap(nullptr, 17408, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(region != MAP_FAILED);
    conn->tls_in_slice = static_cast<u8*>(region);
    conn->tls_in_buf.bind(conn->tls_in_slice, 17408);
    for (u32 i = 0; i < 64; i++) conn->tls_in_buf.write_ptr()[i] = static_cast<u8>(i ^ 0x5a);
    conn->tls_in_buf.commit(64);
    const u32 before = loop.pool.bulk_available();
    REQUIRE_GT(before, 0u);
    REQUIRE(loop.grow_h2_tls_input(*conn));
    CHECK(loop.pool.is_bulk(conn->tls_in_slice));
    CHECK_EQ(loop.pool.bulk_available(), before - 1);
    CHECK_EQ(conn->tls_in_buf.len(), 64u);
    for (u32 i = 0; i < 64; i++) CHECK_EQ(conn->tls_in_buf.data()[i], static_cast<u8>(i ^ 0x5a));
    loop.free_tls_in_buf(*conn);
    CHECK_EQ(loop.pool.bulk_available(), before);
    CHECK(conn->tls_in_slice == nullptr);

    Connection exhausted;
    exhausted.reset();
    void* original =
        mmap(nullptr, 17408, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(original != MAP_FAILED);
    exhausted.tls_in_slice = static_cast<u8*>(original);
    exhausted.tls_in_buf.bind(exhausted.tls_in_slice, 17408);
    exhausted.tls_in_buf.write_ptr()[0] = 0xa7;
    exhausted.tls_in_buf.commit(1);
    static u8* loans[65536];
    u32 loan_count = 0;
    while (loop.pool.bulk_available() != 0 && loan_count < 65536)
        loans[loan_count++] = loop.pool.alloc_bulk();
    CHECK_FALSE(loop.grow_h2_tls_input(exhausted));
    CHECK_EQ(exhausted.tls_in_slice, static_cast<u8*>(original));
    CHECK_EQ(exhausted.tls_in_buf.capacity(), 17408u);
    CHECK_EQ(exhausted.tls_in_buf.data()[0], 0xa7u);
    munmap(original, 17408);
    exhausted.tls_in_slice = nullptr;
    exhausted.tls_in_buf.bind(nullptr, 0);
    for (u32 i = 0; i < loan_count; i++) loop.pool.free(loans[i]);
    loop.force_close_all();
    loop.shutdown();
}
TEST(grpc_proxy, io_uring_deferred_tls_reclaim_preserves_input_capacity) {
    IoUringEventLoop loop;
    auto initialized = loop.init(0, -1);
    if (!initialized.has_value()) SKIP("io_uring unavailable");

    Connection* normal = loop.alloc_conn();
    REQUIRE(normal != nullptr);
    void* normal_region =
        mmap(nullptr, 16384, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(normal_region != MAP_FAILED);
    normal->tls_in_slice = static_cast<u8*>(normal_region);
    normal->tls_in_buf.bind(normal->tls_in_slice, 16384);
    normal->pending_ops = 1;
    normal->fd = -1;
    const u32 normal_id = normal->id;
    loop.free_conn(*normal);
    Connection& deferred_normal = loop.conns[normal->id];
    CHECK_EQ(deferred_normal.tls_in_buf.capacity(), 16384u);
    deferred_normal.pending_ops = 0;
    loop.reclaim_pending();
#ifdef __linux__
    unsigned char normal_residency = 0;
    errno = 0;
    CHECK_EQ(mincore(normal_region, 4096, &normal_residency), -1);
    CHECK_EQ(errno, ENOMEM);
#endif
    Connection* normal_reused = loop.alloc_conn();
    REQUIRE(normal_reused != nullptr);
    CHECK_EQ(normal_reused->id, normal_id);
    loop.free_conn(*normal_reused);

    const u32 bulk_before = loop.pool.bulk_available();
    Connection* bulk = loop.alloc_conn();
    REQUIRE(bulk != nullptr);
    u8* bulk_region = loop.pool.alloc_bulk();
    REQUIRE(bulk_region != nullptr);
    bulk->tls_in_slice = bulk_region;
    bulk->tls_in_buf.bind(bulk_region, SlicePool::kBulkSliceSize);
    bulk->pending_ops = 1;
    bulk->fd = -1;
    loop.free_conn(*bulk);
    Connection& deferred_bulk = loop.conns[bulk->id];
    CHECK_EQ(deferred_bulk.tls_in_buf.capacity(), SlicePool::kBulkSliceSize);
    deferred_bulk.pending_ops = 0;
    loop.reclaim_pending();
    CHECK_EQ(loop.pool.bulk_available(), bulk_before);
    loop.shutdown();
}
TEST(grpc_proxy, idle_upstream_close_policy_respects_drain_and_activity) {
    GrpcProxyState g{};
    g.init();
    g.connected_at_us = 100;
    g.idle_since_us = 5000;
    CHECK(grpc_idle_upstream_should_close(g, false, true, 101, 1000));
    g.active = 1;
    CHECK(!grpc_idle_upstream_should_close(g, false, true, 101, 1000));
    g.active = 0;
    CHECK(!grpc_idle_upstream_should_close(g, false, false, 5001, 1000));
    CHECK(grpc_idle_upstream_should_close(g, false, false, 6000, 1000));
}
TEST(grpc_proxy, tls_downstream_jit_epoll) {
    streaming_case<EpollEventLoop>(_tc, true);
}
TEST(grpc_proxy, tls_downstream_jit_iouring) {
    streaming_case<IoUringEventLoop>(_tc, true);
}
TEST(grpc_proxy, upstream_tls_epoll) {
    streaming_case<EpollEventLoop>(_tc, false, true);
}
TEST(grpc_proxy, upstream_tls_iouring) {
    streaming_case<IoUringEventLoop>(_tc, false, true);
}
TEST(grpc_proxy, upstream_mtls_epoll) {
    streaming_case<EpollEventLoop>(_tc, true, true, true);
}
TEST(grpc_proxy, upstream_mtls_iouring) {
    streaming_case<IoUringEventLoop>(_tc, true, true, true);
}

namespace {
// mode: hostname mismatch, missing client identity, ALPN mismatch, untrusted CA,
// missing CA file, or a mismatched client key.
template <typename Loop>
void tls_rejection_case(rut::test::TestCase* _tc, u32 mode) {
    auto server = std::make_unique<EchoServer>();
    REQUIRE(server->start(true, mode == 1, mode != 2));
    struct TemporaryCa {
        char path[64] = "/tmp/rut-grpc-untrusted-XXXXXX";
        bool created = false;
        ~TemporaryCa() {
            if (created) unlink(path);
        }
    } temporary_ca;
    if (mode == 3) {
        EVP_PKEY* key = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "prime256v1");
        REQUIRE(key);
        X509* cert = X509_dup(SSL_CTX_get0_certificate(server->tls_context->ssl_ctx));
        REQUIRE(cert);
        const bool signed_cert =
            X509_set_pubkey(cert, key) == 1 && X509_sign(cert, key, EVP_sha256()) > 0;
        EVP_PKEY_free(key);
        const i32 file = mkstemp(temporary_ca.path);
        temporary_ca.created = file >= 0;
        FILE* output = file >= 0 ? fdopen(file, "w") : nullptr;
        const bool written = output && PEM_write_X509(output, cert) == 1;
        if (output)
            fclose(output);
        else if (file >= 0)
            close(file);
        X509_free(cert);
        REQUIRE(signed_cert && written);
    } else if (mode == 5 || mode == 6) {
        EVP_PKEY* key = nullptr;
        if (mode == 6) {
            FILE* input = fopen(RUT_GRPC_FIXTURES "/localhost_key.pem", "r");
            REQUIRE(input);
            key = PEM_read_PrivateKey(input, nullptr, nullptr, nullptr);
            fclose(input);
        } else {
            key = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "prime256v1");
        }
        REQUIRE(key);
        const i32 file = mkstemp(temporary_ca.path);
        temporary_ca.created = file >= 0;
        FILE* output = file >= 0 ? fdopen(file, "w") : nullptr;
        const bool written =
            output && PEM_write_PrivateKey(
                          output,
                          key,
                          mode == 6 ? EVP_aes_256_cbc() : nullptr,
                          mode == 6 ? reinterpret_cast<const unsigned char*>("secret") : nullptr,
                          mode == 6 ? 6 : 0,
                          nullptr,
                          nullptr) == 1;
        if (output)
            fclose(output);
        else if (file >= 0)
            close(file);
        EVP_PKEY_free(key);
        REQUIRE(written);
    }
    auto shard = std::make_unique<Shard<Loop>>();
    const i32 listener = create_listen_socket(0).value_or(-1);
    REQUIRE(listener >= 0);
    if (!shard->init(0, listener)) {
        close(listener);
        SKIP("backend unavailable");
    }
    RouteConfig config;
    REQUIRE(config.add_upstream("secure", 0x7f000001, get_port(server->listen_fd)));
    auto& target = config.upstreams[0];
    target.http2 = true;
    target.tls.enabled = true;
    strcpy(target.tls.ca, mode == 3 ? temporary_ca.path : RUT_GRPC_FIXTURES "/localhost_cert.pem");
    strcpy(target.tls.server_name, mode == 0 ? "wrong.example" : "localhost");
    if (mode == 4) strcpy(target.tls.ca, "/nonexistent/rut-grpc-ca.pem");
    if (mode == 5 || mode == 6) {
        strcpy(target.tls.cert, RUT_GRPC_FIXTURES "/localhost_cert.pem");
        strcpy(target.tls.key, temporary_ca.path);
    }
    REQUIRE(config.add_proxy("/test.Echo/", 'P', 0));
    shard->route_config = &config;
    REQUIRE(shard->spawn(-1));
    {
        Client client;
        CHECK(client.init(get_port(listener)));
        if (client.session) {
            CHECK_EQ(client.request(0, 1024, true), 1);
            CHECK(client.until(0, true));
            CHECK_EQ(client.rpcs[0].status, 14u);
        }
    }
    shard->stop();
    shard->join();
    shard->loop->force_close_all();
    CHECK_EQ(server->requests.load(), 0u);
    CHECK_EQ(shard->shard_metrics.grpc_active, 0u);
    CHECK_EQ(shard->shard_metrics.grpc_completed[14], 1u);
    if (shard->loop->listen_fd >= 0) {
        close(shard->loop->listen_fd);
        shard->loop->listen_fd = -1;
    }
    shard->shutdown();
}
}  // namespace
TEST(grpc_proxy, upstream_tls_rejections_epoll) {
    for (u32 mode = 0; mode < 7; mode++) tls_rejection_case<EpollEventLoop>(_tc, mode);
}
TEST(grpc_proxy, upstream_tls_rejections_iouring) {
    for (u32 mode = 0; mode < 7; mode++) tls_rejection_case<IoUringEventLoop>(_tc, mode);
}

TEST(grpc_proxy, observed_status_metadata) {
    const hpack::Header ok[] = {{{"grpc-status", 11}, {"0", 1}}};
    const hpack::Header denied[] = {{{"grpc-status", 11}, {"7", 1}}};
    const hpack::Header unauthenticated[] = {{{"grpc-status", 11}, {"16", 2}}};
    const hpack::Header invalid[] = {{{"grpc-status", 11}, {"17", 2}}};
    const hpack::Header nonnumeric[] = {{{"grpc-status", 11}, {"x", 1}}};
    const hpack::Header duplicate[] = {ok[0], denied[0]};
    const hpack::Header leading_zero[] = {{{"grpc-status", 11}, {"00", 2}}};
    CHECK_EQ(grpc_observed_status(ok, 1), 0u);
    CHECK_EQ(grpc_observed_status(leading_zero, 1), 0u);
    CHECK_EQ(grpc_observed_status(denied, 1), 7u);
    CHECK_EQ(grpc_observed_status(unauthenticated, 1), 16u);
    CHECK_EQ(grpc_observed_status(invalid, 1), 2u);
    CHECK_EQ(grpc_observed_status(nonnumeric, 1), 2u);
    CHECK_EQ(grpc_observed_status(duplicate, 2), 2u);
    CHECK_EQ(grpc_observed_status(nullptr, 0), 2u);
}
TEST(grpc_proxy, log_target_snapshot_and_bounds) {
    AccessLogEntry entry{};
    char path[] = "/service/Method";
    grpc_log_target(entry, {path, sizeof(path) - 1});
    path[1] = 'x';
    CHECK_EQ(entry.target_state, AccessLogTargetState::Complete);
    CHECK(memcmp(entry.path, "/service/Method", sizeof(path) - 1) == 0);
    char long_path[kAccessLogCompleteTargetMax + 1];
    memset(long_path, 'x', sizeof(long_path));
    long_path[0] = '/';
    grpc_log_target(entry, {long_path, sizeof(long_path)});
    CHECK_EQ(entry.target_state, AccessLogTargetState::OverLimit);
    CHECK_EQ(entry.target_length, sizeof(long_path));
    grpc_log_target(entry, {"/bad\npath", 9});
    CHECK_EQ(entry.target_state, AccessLogTargetState::Invalid);
    grpc_log_target(entry, {});
    CHECK_EQ(entry.target_state, AccessLogTargetState::Invalid);
}

TEST(grpc_proxy, log_overflow_does_not_duplicate_or_lose_rpc_accounting) {
    ShardMetrics metrics;
    metrics.init();
    auto ring = std::make_unique<AccessLogRing>();
    ring->init();
    AccessLogEntry entry{};
    for (u32 i = 0; i < AccessLogRing::kCapacity; i++) CHECK(ring->push(entry));
    struct Loop {
        ShardMetrics* metrics;
        AccessLogRing* access_log;
        SourceLiveAccessLogProducer* live_access_log;
    } loop{&metrics, ring.get(), nullptr};
    auto exchange = std::make_unique<GrpcExchange>();
    exchange->init();
    exchange->observed = true;
    exchange->started_us = monotonic_us();
    exchange->failure = 4;
    exchange->response_end_sent = true;
    metrics.on_grpc_start();
    grpc_observe(&loop, *exchange);
    grpc_observe(&loop, *exchange);
    CHECK_EQ(metrics.grpc_active, 0u);
    CHECK_EQ(metrics.grpc_completed[4], 1u);
    CHECK_EQ(metrics.grpc_latency.count, 1u);
    CHECK_EQ(ring->available(), AccessLogRing::kCapacity);
}

TEST(grpc_proxy, late_failed_upload_data_is_included_in_access_log) {
    auto transport = std::make_unique<EpollEventLoop>();
    auto down = std::make_unique<Connection>();
    down->reset();
    auto h2 = std::make_unique<Http2Conn>();
    h2->init();
    down->h2 = h2.get();
    auto exchange = std::make_unique<GrpcExchange>();
    exchange->init();
    exchange->request_bytes = 100;
    exchange->failure = 14;
    grpc_request_data(transport.get(), *down, *exchange, nullptr, 77, false);
    exchange->failure = 0;  // upstream already detached; late DATA is discarded
    grpc_request_data(transport.get(), *down, *exchange, nullptr, 23, false);
    exchange->failure = 14;
    exchange->observed = true;
    exchange->response_end_sent = true;
    exchange->started_us = monotonic_us();
    auto ring = std::make_unique<AccessLogRing>();
    ring->init();
    struct LogLoop {
        ShardMetrics* metrics;
        AccessLogRing* access_log;
        SourceLiveAccessLogProducer* live_access_log;
    } logs{nullptr, ring.get(), nullptr};
    grpc_observe(&logs, *exchange);
    AccessLogEntry entry{};
    REQUIRE(ring->pop(entry));
    CHECK_EQ(entry.req_size, 200u);
    CHECK_EQ(entry.grpc_status_plus_one, 15u);
    CHECK_EQ(transport->backend.pending_count, 0u);
}

TEST(grpc_proxy, live_log_keeps_bytes_only_output) {
    auto ring = std::make_unique<LiveAccessLogRing>();
    ring->init();
    i32 fds[2];
    REQUIRE(rut::test::nonblocking_pipe(fds) == 0);
    struct Reader {
        i32 fd;
        ~Reader() { close(fd); }
    } reader{fds[0]};
    LiveAccessLogRing* rings[] = {ring.get()};
    SourceLiveAccessLogSession session;
    REQUIRE(session.start(SourceAccessLogFd(fds[1]), rings, 1u));
    SourceLiveAccessLogProducer producer;
    REQUIRE(producer.init(ring.get(), &session, 0u));
    ShardMetrics metrics;
    metrics.init();
    struct Loop {
        ShardMetrics* metrics;
        AccessLogRing* access_log;
        SourceLiveAccessLogProducer* live_access_log;
    } loop{&metrics, nullptr, &producer};
    auto exchange = std::make_unique<GrpcExchange>();
    exchange->init();
    exchange->observed = true;
    exchange->started_us = monotonic_us();
    exchange->response_end_sent = true;
    exchange->response_status = 0;
    exchange->request_bytes = 123;
    metrics.on_grpc_start();
    grpc_observe(&loop, *exchange);
    const auto finished = session.finish();
    CHECK_EQ(finished.status, SourceLiveAccessLogFinishStatus::Success);
    char bytes[32];
    const ssize_t n = read(reader.fd, bytes, sizeof(bytes));
    CHECK_EQ(n, 4);
    if (n == 4) CHECK(memcmp(bytes, "123\n", 4) == 0);
    CHECK_EQ(metrics.grpc_completed[0], 1u);
    CHECK_EQ(metrics.grpc_active, 0u);
}

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    return rut::test::run_all(argc, argv);
}

TEST(grpc_proxy, active_session_keepalive_gates_and_timeout) {
    auto h = std::make_unique<Http2Conn>();
    h->init_client();
    auto& g = h->grpc;
    g.connected_at_us = 100;
    constexpr u64 due = 300000100;
    constexpr u64 timeout = 20000000;
    CHECK(!grpc_keepalive_tick(*h, due, timeout, true));
    CHECK_EQ(g.control_len, 0u);  // idle sessions are not probed
    g.active = 1;
    CHECK(!grpc_keepalive_tick(*h, due, timeout, true));
    CHECK_EQ(g.control_len, 0u);  // SETTINGS not received
    h->peer_settings_seen = true;
    g.connecting = true;
    CHECK(!grpc_keepalive_tick(*h, due, timeout, true));
    g.connecting = false;
    h->peer_goaway = true;
    CHECK(!grpc_keepalive_tick(*h, due, timeout, true));
    h->peer_goaway = false;
    CHECK(!grpc_keepalive_tick(*h, due, timeout, false));
    CHECK_EQ(g.control_len, 0u);
    CHECK_EQ(g.keepalive_due_us, due);
    CHECK(!grpc_keepalive_tick(*h, due + timeout - 1, timeout, false));
    CHECK(grpc_keepalive_tick(*h, due + timeout, timeout, false));
    g.keepalive_due_us = 0;
    const u64 delayed_tick = due + 2 * timeout;
    CHECK(!grpc_keepalive_tick(*h, delayed_tick, timeout, false));
    CHECK_EQ(g.keepalive_due_us, delayed_tick);
    CHECK(!grpc_keepalive_tick(*h, delayed_tick + timeout - 1, timeout, false));
    CHECK(grpc_keepalive_tick(*h, delayed_tick + timeout, timeout, false));
    g.keepalive_due_us = 0;
    g.last_ping_us = 0;
    g.control_len = sizeof(g.control) - 16;
    CHECK(!grpc_keepalive_tick(*h, due, timeout, true));
    CHECK(!h->ping_pending);
    CHECK(grpc_keepalive_tick(*h, due + timeout, timeout, true));
    g.keepalive_due_us = 0;
    g.control_len = 0;
    CHECK(!grpc_keepalive_tick(*h, due - 1, timeout, true));
    CHECK(!h->ping_pending);
    CHECK(!grpc_keepalive_tick(*h, due, timeout, true));
    CHECK(h->ping_pending);
    CHECK_EQ(g.control_len, 17u);
    CHECK(!grpc_keepalive_tick(*h, due + timeout - 1, timeout, true));
    CHECK(grpc_keepalive_tick(*h, due + timeout, timeout, true));
    // Receive the matching ACK through the real HTTP/2 parser.
    g.control[4] = http2_flag::kAck;
    u8 out[256];
    u32 written = 0;
    auto result = h->process(g.control, 17, out, sizeof(out), &written);
    CHECK(!result.close);
    CHECK(!h->ping_pending);
    g.control_len = 0;
    CHECK(!grpc_keepalive_tick(*h, due + timeout, timeout, true));
    CHECK_EQ(g.control_len, 0u);
    CHECK(!grpc_keepalive_tick(*h, due + 300000000, timeout, true));
    CHECK(h->ping_pending);
}

TEST(grpc_proxy, keepalive_probe_queues_behind_progressing_upload_send) {
    GrpcDriveFixture loop;
    Connection upstream;
    upstream.reset();
    u8 recv[256]{};
    u8 send[64]{};
    upstream.bind_request_receive_buffer(recv, sizeof(recv));
    upstream.send_slice = send;
    upstream.send_buf.bind(send, sizeof(send));

    Http2Conn upstream_h2;
    upstream_h2.init_client();
    upstream_h2.grpc.upstream = true;
    upstream_h2.grpc.preface_sent = true;
    upstream_h2.grpc.active = 1;
    upstream_h2.grpc.connected_at_us = monotonic_us() - 300000001;
    upstream_h2.peer_settings_seen = true;
    upstream.h2 = &upstream_h2;
    auto* stream = upstream_h2.open_stream(1);
    REQUIRE(stream != nullptr);
    stream->state = Http2StreamState::Open;

    Connection downstream;
    downstream.reset();
    Http2Conn downstream_h2;
    downstream_h2.init_client();
    downstream.h2 = &downstream_h2;

    GrpcExchange exchange;
    exchange.init();
    exchange.upstream = &upstream;
    exchange.downstream = &downstream;
    exchange.upstream_stream = exchange.downstream_stream = 1;
    exchange.request_headers_sent = true;
    exchange.upload_len = 100;
    for (u32 i = 0; i < exchange.upload_len; i++) exchange.upload[i] = static_cast<u8>(i);
    REQUIRE(grpc_attach(upstream_h2, &exchange));

    const u8 first_data[] = {1, 2, 3, 4};
    const u32 first_len = http2_write_data(send, 1, first_data, sizeof(first_data), false);
    REQUIRE_GT(first_len, 0u);
    upstream.send_buf.commit(first_len);
    upstream.on_send = &grpc_on_upstream_sent<GrpcDriveFixture>;
    REQUIRE(loop.submit_send(upstream, send, first_len));
    u8 borrowed_send[sizeof(send)];
    __builtin_memcpy(borrowed_send, send, first_len);

    grpc_tick(&loop, upstream);
    CHECK_FALSE(loop.closed);
    CHECK_EQ(loop.sends, 1u);
    CHECK_EQ(upstream.send_buf.len(), first_len);
    CHECK_EQ(upstream_h2.grpc.control_len, 17u);
    CHECK(upstream_h2.ping_pending);
    CHECK_EQ(memcmp(send, borrowed_send, first_len), 0);

    grpc_on_upstream_sent<GrpcDriveFixture>(
        &loop, upstream, {upstream.id, static_cast<i32>(first_len), 0, 0, IoEventType::Send, 0});
    CHECK_EQ(loop.sends, 2u);
    CHECK_EQ(upstream_h2.grpc.control_len, 0u);
    Http2FrameHeader ping{};
    REQUIRE_EQ(parse_frame_header(upstream.send_buf.data(), upstream.send_buf.len(), &ping),
               ParseStatus::Complete);
    CHECK_EQ(ping.type, static_cast<u8>(Http2FrameType::Ping));
    CHECK_EQ(upstream.send_buf.len(), 17u);
    u8 ack[17];
    __builtin_memcpy(ack, upstream.send_buf.data(), sizeof(ack));
    ack[4] = http2_flag::kAck;

    grpc_on_upstream_sent<GrpcDriveFixture>(
        &loop,
        upstream,
        {upstream.id, static_cast<i32>(upstream.send_buf.len()), 0, 0, IoEventType::Send, 0});
    CHECK_EQ(loop.sends, 3u);
    Http2FrameHeader data{};
    REQUIRE_EQ(parse_frame_header(upstream.send_buf.data(), upstream.send_buf.len(), &data),
               ParseStatus::Complete);
    CHECK_EQ(data.type, static_cast<u8>(Http2FrameType::Data));
    CHECK_EQ(exchange.upload_len, 45u);

    __builtin_memcpy(upstream.recv_slice, ack, sizeof(ack));
    upstream.recv_buf.commit(sizeof(ack));
    grpc_on_upstream_data<GrpcDriveFixture>(
        &loop, upstream, {upstream.id, static_cast<i32>(sizeof(ack)), 0, 0, IoEventType::Recv, 0});
    CHECK_FALSE(upstream_h2.ping_pending);
    upstream_h2.grpc.last_ping_us =
        monotonic_us() - static_cast<u64>(loop.upstream_timeout) * 1000000 - 1;
    grpc_tick(&loop, upstream);
    CHECK_FALSE(loop.closed);
}

TEST(grpc_proxy, blocked_keepalive_probe_timeout_closes_and_releases_session) {
    struct ClosingLoop : GrpcDriveFixture {
        void close_conn(Connection& conn) {
            grpc_connection_closed<GrpcDriveFixture>(this, conn);
            closed = true;
        }
    } loop;
    Connection conn;
    conn.reset();
    auto h = std::make_unique<Http2Conn>();
    h->init_client();
    conn.h2 = h.get();
    conn.on_send = &pending_send;
    auto& g = h->grpc;
    g.upstream = true;
    g.active = 1;
    g.preface_sent = true;
    h->peer_settings_seen = true;
    g.connected_at_us = monotonic_us() - 300000001;
    Connection downstream;
    downstream.reset();
    auto down_h2 = std::make_unique<Http2Conn>();
    down_h2->init();
    downstream.h2 = down_h2.get();
    auto x = std::make_unique<GrpcExchange>();
    x->init();
    x->upstream = &conn;
    x->downstream = &downstream;
    x->upstream_stream = x->downstream_stream = 1;
    x->slot_held = true;
    REQUIRE(grpc_attach(*h, x.get()));
    REQUIRE(grpc_attach(*down_h2, x.get()));
    loop.grpc_upstreams = &conn;
    grpc_tick(&loop, conn);
    CHECK(!loop.closed);
    CHECK_EQ(loop.sends, 0u);
    CHECK(h->ping_pending);
    CHECK_EQ(g.control_len, 17u);
    CHECK_EQ(g.keepalive_due_us, 0u);
    // The probe is queued behind the genuinely blocked send. Its ACK deadline
    // still closes a session when the queued PING cannot drain.
    g.last_ping_us = monotonic_us() - 1000001;
    grpc_tick(&loop, conn);
    CHECK(loop.closed);
    CHECK_EQ(loop.released, 1u);
    CHECK(x->upstream == nullptr);
    CHECK(!x->slot_held);
    CHECK(x->response_end);
}

TEST(grpc_proxy, keepalive_timer_flushes_probe_and_closes_unresponsive_session) {
    struct ClosingLoop : GrpcDriveFixture {
        void close_conn(Connection& conn) {
            grpc_connection_closed<GrpcDriveFixture>(this, conn);
            closed = true;
        }
    } loop;
    Connection conn;
    conn.reset();
    auto h = std::make_unique<Http2Conn>();
    h->init_client();
    conn.h2 = h.get();
    u8 send[SlicePool::kSliceSize];
    conn.send_buf.bind(send, sizeof(send));
    auto& g = h->grpc;
    g.upstream = true;
    Connection downstream;
    downstream.reset();
    auto down_h2 = std::make_unique<Http2Conn>();
    down_h2->init();
    downstream.h2 = down_h2.get();
    downstream.on_send = &pending_send;
    auto x = std::make_unique<GrpcExchange>();
    x->init();
    x->upstream = &conn;
    x->downstream = &downstream;
    x->upstream_stream = x->downstream_stream = 1;
    x->slot_held = true;
    REQUIRE(grpc_attach(*h, x.get()));
    REQUIRE(grpc_attach(*down_h2, x.get()));
    loop.grpc_upstreams = &conn;
    g.preface_sent = true;
    h->peer_settings_seen = true;
    g.connected_at_us = monotonic_us() - 300000001;
    grpc_tick(&loop, conn);
    CHECK(!loop.closed);
    CHECK_EQ(loop.sends, 1u);
    CHECK_EQ(loop.last_send_len, 17u);
    CHECK_EQ(send[3], static_cast<u8>(Http2FrameType::Ping));
    CHECK(h->ping_pending);
    CHECK_EQ(g.control_len, 0u);
    // No wall-clock sleep: move the recorded send time beyond the ACK deadline.
    g.last_ping_us = monotonic_us() - 1000001;
    grpc_tick(&loop, conn);
    CHECK(loop.closed);
    CHECK_EQ(loop.sends, 1u);
    CHECK(loop.grpc_upstreams == nullptr);
    CHECK_EQ(g.active, 0u);
    CHECK_EQ(loop.released, 1u);
    CHECK(x->upstream == nullptr);
    CHECK(!x->slot_held);
    CHECK(x->response_end);
    CHECK_EQ(x->failure, 14u);
    grpc_connection_closed<GrpcDriveFixture>(&loop, conn);
    CHECK_EQ(loop.released, 1u);
}

TEST(grpc_proxy, message_limits_fragmentation_and_opaque_payloads) {
    const u8 frames[] = {0, 0, 0, 0, 3, 0xff, 0xfe, 0xfd, 1, 0, 0, 0, 2, 0xf0, 0xf1, 0, 0, 0, 0, 0};
    for (u32 chunk = 1; chunk <= sizeof(frames); chunk++) {
        GrpcMessageLimit limit;
        limit.init(3);
        for (u32 off = 0; off < sizeof(frames);) {
            const u32 amount = chunk < sizeof(frames) - off ? chunk : sizeof(frames) - off;
            CHECK_EQ(limit.feed(frames + off, amount, off + amount == sizeof(frames)), 0u);
            off += amount;
        }
        CHECK_EQ(limit.feed(nullptr, 0, true), 0u);
    }
    GrpcMessageLimit limit;
    const u8 oversized[] = {0, 0xff, 0xff, 0xff, 0xff};
    limit.init(100);
    CHECK_EQ(limit.feed(oversized, sizeof(oversized), false), 8u);
    limit.init(0xffffffffu);
    CHECK_EQ(limit.feed(oversized, sizeof(oversized), false), 0u);
    CHECK_EQ(limit.remaining, 0xffffffffu);
    CHECK_EQ(limit.feed(nullptr, 0, true), 13u);
    const u8 invalid[] = {2, 0, 0, 0, 0};
    limit.init(3);
    CHECK_EQ(limit.feed(invalid, sizeof(invalid), true), 13u);
    for (u32 bytes = 1; bytes < 8; bytes++) {
        limit.init(3);
        CHECK_EQ(limit.feed(frames, bytes, true), 13u);
    }
    limit.init();
    CHECK_EQ(limit.feed(invalid, sizeof(invalid), true), 0u);  // omitted limits stay opaque
}

TEST(grpc_proxy, message_limits_detach_oversized_upload_and_download) {
    for (bool response : {false, true}) {
        GrpcDriveFixture loop;
        Connection up, down;
        up.reset();
        down.reset();
        auto upstream = std::make_unique<Http2Conn>();
        auto downstream = std::make_unique<Http2Conn>();
        upstream->init_client();
        upstream->grpc.upstream = true;
        downstream->init_client();
        up.h2 = upstream.get();
        down.h2 = downstream.get();
        up.on_send = &pending_send;
        REQUIRE(upstream->open_stream(1));
        REQUIRE(downstream->open_stream(1));
        auto x = std::make_unique<GrpcExchange>();
        x->init();
        x->upstream = &up;
        x->downstream = &down;
        x->upstream_stream = x->downstream_stream = 1;
        x->request_headers_sent = true;
        x->slot_held = true;
        x->request_message.init(3);
        x->response_message.init(3);
        REQUIRE(grpc_attach(*upstream, x.get()));
        REQUIRE(grpc_attach(*downstream, x.get()));
        const u8 prefix[] = {0, 0, 0, 0, 4};
        if (response) {
            GrpcClientDispatch<GrpcDriveFixture> dispatch{&loop, &up};
            grpc_response_data<GrpcDriveFixture>(&dispatch, *upstream, 1, prefix, 5, false);
            CHECK(x->response_end);
        } else {
            grpc_request_data(&loop, down, *x, prefix, 5, false);
        }
        CHECK_EQ(x->failure, 8u);
        CHECK(x->upstream == nullptr);
        CHECK(!x->slot_held);
        CHECK_EQ(loop.released, 1u);
        CHECK_EQ(upstream->grpc.active, 0u);
        CHECK_EQ(upstream->grpc.control_len, 13u);
        CHECK_EQ(x->upload_len, 0u);
        CHECK_EQ(x->download_len, 0u);
    }
}

TEST(grpc_proxy, message_limits_reject_response_trailers_inside_payload) {
    GrpcDriveFixture loop;
    Connection up;
    up.reset();
    auto h = std::make_unique<Http2Conn>();
    h->init_client();
    h->grpc.upstream = true;
    up.h2 = h.get();
    REQUIRE(h->open_stream(1));
    auto x = std::make_unique<GrpcExchange>();
    x->init();
    x->upstream = &up;
    x->upstream_stream = x->downstream_stream = 1;
    x->response_message.init(100);
    const u8 partial[] = {0, 0, 0, 0, 5, 1};
    CHECK_EQ(x->response_message.feed(partial, sizeof(partial), false), 0u);
    REQUIRE(grpc_attach(*h, x.get()));
    GrpcClientDispatch<GrpcDriveFixture> dispatch{&loop, &up};
    const hpack::Header trailers[] = {{{"grpc-status", 11}, {"0", 1}}};
    grpc_response_trailers<GrpcDriveFixture>(&dispatch, *h, 1, trailers, 1, true);
    CHECK_EQ(x->failure, 13u);
}

template <typename Loop>
void message_limit_snapshot_case(rut::test::TestCase* _tc) {
    auto loop = std::make_unique<Loop>();
    if (!loop->init(0, -1).has_value()) SKIP("backend unavailable");
    RouteConfig cfg;
    REQUIRE(cfg.add_upstream("grpc", 0x7f000001, 1).has_value());
    cfg.upstreams[0].http2 = true;
    cfg.upstreams[0].max_request_message_bytes = 100;
    cfg.upstreams[0].max_response_message_bytes = 200;
    Connection* up = loop->alloc_conn();
    Connection* down = loop->alloc_conn();
    REQUIRE(up && down);
    REQUIRE(loop->alloc_h2(*up));
    REQUIRE(loop->alloc_h2(*down));
    up->h2->init_client();
    down->h2->init_client();
    up->h2->grpc.upstream = true;
    up->h2->grpc.preface_sent = true;
    up->h2->peer_settings_seen = true;
    up->upstream_idx = up->upstream_backend_idx = 0;
    up->request_config = down->request_config = &cfg;
    up->on_send = down->on_send = &pending_send;
    up->on_close = &grpc_connection_closed<Loop>;
    loop->grpc_upstreams = up;
    REQUIRE(down->h2->open_stream(1));
    ParsedRequest req;
    req.reset();
    req.method = HttpMethod::POST;
    req.headers[0] = {Str{"content-type", 12}, Str{"application/grpc", 16}};
    req.header_count = 1;
    const hpack::Header hs[] = {{{":method", 7}, {"POST", 4}},
                                {{":scheme", 7}, {"http", 4}},
                                {{":path", 5}, {"/Echo", 5}},
                                {{":authority", 10}, {"x", 1}},
                                {{"content-type", 12}, {"application/grpc", 16}}};
    REQUIRE(grpc_start_impl(loop.get(), *down, 1, &cfg, 0, hs, 5, req, false));
    auto* x = grpc_find(*down->h2, 1);
    REQUIRE(x);
    CHECK_EQ(x->request_message.limit, 100u);
    CHECK_EQ(x->response_message.limit, 200u);
    cfg.upstreams[0].max_request_message_bytes = 1;
    cfg.upstreams[0].max_response_message_bytes = 2;
    CHECK_EQ(x->request_message.limit, 100u);
    CHECK_EQ(x->response_message.limit, 200u);
    loop->force_close_all();
    loop->shutdown();
}
TEST(grpc_proxy, message_limits_snapshot_epoll) {
    message_limit_snapshot_case<EpollEventLoop>(_tc);
}
TEST(grpc_proxy, message_limits_snapshot_iouring) {
    message_limit_snapshot_case<IoUringEventLoop>(_tc);
}

#include "grpc_web_h1_cases.h"

#if RUT_GRPC_JIT
#include "protobuf/enum_oracle.inc"
#include "protobuf/repeated_oracle.inc"

template <typename Loop>
void repeated_protobuf_network_case(rut::test::TestCase* _tc) {
    auto server = std::make_unique<EchoServer>();
    REQUIRE(server->start());
    auto shard = std::make_unique<Shard<Loop>>();
    const int lfd = create_listen_socket(0).value_or(-1);
    REQUIRE(lfd >= 0);
    if (!shard->init(0, lfd).has_value()) {
        close(lfd);
        SKIP("backend unavailable");
    }
    REQUIRE(shard->init_access_log().has_value());
    struct Program {
        LoadedProgram value;
        ~Program() { value.destroy(); }
    };
    auto program = std::make_unique<Program>();
    char path[] = "/tmp/rut-pb-network-XXXXXX";
    const int file = mkstemp(path);
    REQUIRE(file >= 0);
    char source[8192];
    const int length = snprintf(
        source,
        sizeof(source),
        "upstream grpc { host: \"127.0.0.1\", port: %u, protocol: .http2 }\n"
        "route POST \"/test.Echo/Call\" { return forward(grpc) }\n"
        "route POST \"/codec\" { "
        "guard let value = protobuf.decode(\"" RUT_GRPC_FIXTURES
        "/../protobuf/codec.proto\", "
        "\"example.RepeatedChild\", req.body) else { return 422 } "
        "guard let bytes = protobuf.encode(\"" RUT_GRPC_FIXTURES
        "/../protobuf/codec.proto\", "
        "\"example.RepeatedChild\", value) else { return 500 } "
        "return response(200, body: bytes) }\n"
        "route POST \"/framed\" { "
        "guard let payload = grpc.unframe(req.body) else { return 422 } "
        "guard let value = protobuf.decode(\"" RUT_GRPC_FIXTURES
        "/../protobuf/codec.proto\", \"example.RepeatedChild\", payload) else { return 400 } "
        "guard let bytes = protobuf.encode(\"" RUT_GRPC_FIXTURES
        "/../protobuf/codec.proto\", \"example.RepeatedChild\", value) else { return 500 } "
        "guard let framed = grpc.frame(bytes) else { return 500 } "
        "return response(200, body: framed) }\n"
        "route POST \"/local.Echo/Call\" { "
        "guard let payload = grpc.unframe(req.body) else { return 422 } "
        "guard let value = protobuf.decode(\"" RUT_GRPC_FIXTURES
        "/../protobuf/codec.proto\", \"example.RepeatedChild\", payload) else { return 400 } "
        "guard let bytes = protobuf.encode(\"" RUT_GRPC_FIXTURES
        "/../protobuf/codec.proto\", \"example.RepeatedChild\", value) else { return 500 } "
        "guard let framed = grpc.frame(bytes) else { return 500 } "
        "return response(200, headers: {\"content-type\": \"application/grpc+proto\", "
        "\"grpc-status\": \"0\"}, body: framed) }\n"
        "route POST \"/method.Echo/Call\" { "
        "guard let value = grpc.decode(\"" RUT_GRPC_FIXTURES
        "/../protobuf/codec.proto\", \"/example.UnaryCodec/Echo\", req.body) else { "
        "return response(200, headers: {\"content-type\": \"application/grpc\", \"grpc-status\": "
        "\"13\"}) } "
        "guard let framed = grpc.encode(\"" RUT_GRPC_FIXTURES
        "/../protobuf/codec.proto\", \"/example.UnaryCodec/Echo\", value) else { return 500 } "
        "return response(200, headers: {\"content-type\": \"application/grpc+proto\", "
        "\"grpc-status\": \"0\"}, body: framed) }\n"
        "route POST \"/example.StringCodec/Echo\" { "
        "guard let value = grpc.decode(\"" RUT_GRPC_FIXTURES
        "/../protobuf/strings.proto\", \"/example.StringCodec/Echo\", req.body) else { "
        "return response(200, headers: {\"content-type\": \"application/grpc+proto\", "
        "\"grpc-status\": \"13\"}) } "
        "guard let framed = grpc.encode(\"" RUT_GRPC_FIXTURES
        "/../protobuf/strings.proto\", \"/example.StringCodec/Echo\", value) else { return 500 "
        "} "
        "return response(200, headers: {\"content-type\": \"application/grpc+proto\", "
        "\"grpc-status\": \"0\"}, body: framed) }\n"
        "route POST \"/local.Error/Call\" { return response(200, headers: {"
        "\"content-type\": \"application/grpc\", \"grpc-status\": \"7\"}) }\n",
        get_port(server->listen_fd));
    const bool written = length > 0 && length < static_cast<int>(sizeof(source)) &&
                         write(file, source, length) == length;
    close(file);
    LoadError error;
    const bool loaded = written && load_rut_program(path, program->value, error);
    unlink(path);
    REQUIRE(loaded);
    shard->route_config = &program->value.config;
    REQUIRE(shard->spawn(-1).has_value());
    // Every branch below reaches stop/join before the loaded program is destroyed.
    {
        Client client;
        const bool connected = client.init(get_port(lfd));
        CHECK(connected);
        if (connected) {
            // Raw protobuf codec over real HTTP/2, with one-byte DATA fragments.
            auto codec = [&](u32 index,
                             const u8* input,
                             u32 size,
                             u32 status,
                             const u8* expected,
                             u32 expected_size,
                             const char* route_path = "/codec") {
                CHECK(client.request_native_raw(
                          index, input, size, "1H", nullptr, route_path, "application/protobuf") >
                      0);
                client.rpcs[index].max_chunk = 1;
                const bool complete = client.until(index, true);
                CHECK(complete);
                if (complete) {
                    CHECK_EQ(client.rpcs[index].http_status, status);
                    CHECK_EQ(client.rpcs[index].response_len, expected_size);
                    if (expected_size && client.rpcs[index].response_len == expected_size)
                        CHECK(memcmp(client.rpcs[index].response.get(), expected, expected_size) ==
                              0);
                }
            };
            codec(0,
                  kRepeatedOracle,
                  sizeof(kRepeatedOracle),
                  200,
                  kRepeatedOracle,
                  sizeof(kRepeatedOracle));
            const u8 malformed[] = {10, 0, 10, 3, 10, 1, 255};
            // Rejected later children must not poison the next request's arena.
            codec(1, malformed, sizeof(malformed), 422, nullptr, 0);
            codec(2,
                  kRepeatedNoncanonical,
                  sizeof(kRepeatedNoncanonical),
                  200,
                  kRepeatedNormalized,
                  sizeof(kRepeatedNormalized));
            // Native gRPC forwarding handles envelopes opaquely; the codec route
            // above intentionally uses raw protobuf rather than a gRPC envelope.
            u8 framed[5 + sizeof(kRepeatedOracle)] = {};
            framed[4] = sizeof(kRepeatedOracle);
            memcpy(framed + 5, kRepeatedOracle, sizeof(kRepeatedOracle));
            CHECK(client.request_native_raw(3, framed, sizeof(framed)) > 0);
            client.rpcs[3].max_chunk = 1;
            const bool echoed = client.until(3, true);
            CHECK(echoed);
            if (echoed) {
                CHECK(client.rpcs[3].ok);
                CHECK_EQ(client.rpcs[3].response_len, sizeof(framed));
                if (client.rpcs[3].response_len == sizeof(framed))
                    CHECK(memcmp(client.rpcs[3].response.get(), framed, sizeof(framed)) == 0);
            }
            // Cancel an incomplete codec body, then reuse the same connection.
            const int stream = client.request_native_raw(4,
                                                         kRepeatedOracle,
                                                         sizeof(kRepeatedOracle),
                                                         "1H",
                                                         nullptr,
                                                         "/codec",
                                                         "application/protobuf");
            CHECK(stream > 0);
            client.rpcs[4].end = false;
            client.rpcs[4].max_chunk = 1;
            CHECK(client.step());
            CHECK_EQ(nghttp2_submit_rst_stream(
                         client.session, NGHTTP2_FLAG_NONE, stream, NGHTTP2_CANCEL),
                     0);
            codec(5,
                  kRepeatedOracle,
                  sizeof(kRepeatedOracle),
                  200,
                  kRepeatedOracle,
                  sizeof(kRepeatedOracle));
            codec(6, framed, sizeof(framed), 200, framed, sizeof(framed), "/framed");
            framed[0] = 1;
            codec(7, framed, sizeof(framed), 422, nullptr, 0, "/framed");
            framed[0] = 0;
            codec(8, framed, sizeof(framed) - 1, 422, nullptr, 0, "/framed");
            codec(9, framed, sizeof(framed), 200, framed, sizeof(framed), "/framed");
            auto local_rpc = [&](u32 index) {
                CHECK(client.request_native_raw(
                          index, framed, sizeof(framed), "1H", nullptr, "/local.Echo/Call") > 0);
                client.rpcs[index].max_chunk = 1;
                const bool completed = client.until(index, true);
                CHECK(completed);
                if (completed) {
                    CHECK(client.rpcs[index].ok);
                    CHECK(client.rpcs[index].status_in_trailers);
                    CHECK_EQ(client.rpcs[index].http_status, 200u);
                    CHECK_EQ(client.rpcs[index].response_len, sizeof(framed));
                    if (client.rpcs[index].response_len == sizeof(framed))
                        CHECK(memcmp(client.rpcs[index].response.get(), framed, sizeof(framed)) ==
                              0);
                }
            };
            local_rpc(10);
            local_rpc(11);
            // Hold response DATA at zero window, cancel, then reuse the connection.
            nghttp2_settings_entry zero_window{NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 0};
            CHECK_EQ(nghttp2_submit_settings(client.session, NGHTTP2_FLAG_NONE, &zero_window, 1),
                     0);
            const int stalled = client.request_native_raw(
                12, framed, sizeof(framed), "1H", nullptr, "/local.Echo/Call");
            CHECK(stalled > 0);
            const u64 deadline = monotonic_us() + 5000000;
            while (!client.rpcs[12].http_status && monotonic_us() < deadline)
                if (!client.step()) break;
            CHECK_EQ(client.rpcs[12].http_status, 200u);
            CHECK_EQ(client.rpcs[12].response_len, 0u);
            CHECK_EQ(nghttp2_submit_rst_stream(
                         client.session, NGHTTP2_FLAG_NONE, stalled, NGHTTP2_CANCEL),
                     0);
            nghttp2_settings_entry window{NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 65535};
            CHECK_EQ(nghttp2_submit_settings(client.session, NGHTTP2_FLAG_NONE, &window, 1), 0);
            local_rpc(13);
            CHECK(client.request_native_raw(
                      14, framed, sizeof(framed), "1H", nullptr, "/local.Error/Call") > 0);
            CHECK(client.until(14, true));
            CHECK_EQ(client.rpcs[14].status, 7u);
            CHECK(client.rpcs[14].status_in_trailers);
            CHECK_EQ(client.rpcs[14].response_len, 0u);
            // Maximum codec payload plus envelope exceeds the inline JIT body.
            // It must survive arena release in a separately owned pool slice.
            u8 maximum[8197] = {0, 0, 0, 32, 0, 10, 253, 63, 10, 250, 63};
            memset(maximum + 11, 'x', sizeof(maximum) - 11);
            CHECK(client.request_native_raw(
                      15, maximum, sizeof(maximum), "1H", nullptr, "/local.Echo/Call") > 0);
            client.rpcs[15].max_chunk = 17;
            CHECK(client.until(15, true));
            CHECK(client.rpcs[15].ok && client.rpcs[15].status_in_trailers);
            CHECK_EQ(client.rpcs[15].response_len, sizeof(maximum));
            if (client.rpcs[15].response_len == sizeof(maximum))
                CHECK(memcmp(client.rpcs[15].response.get(), maximum, sizeof(maximum)) == 0);
            Client method_client;
            const bool method_connected = method_client.init(get_port(lfd));
            CHECK(method_connected);
            if (method_connected) {
                auto invoke_method =
                    [&](u32 index, const u8* bytes, u32 size, u32 expected_status) {
                        CHECK(method_client.request_native_raw(
                                  index, bytes, size, "1H", nullptr, "/method.Echo/Call") > 0);
                        method_client.rpcs[index].max_chunk = 1;
                        const bool complete = method_client.until(index, true);
                        CHECK(complete);
                        if (complete) {
                            CHECK_EQ(method_client.rpcs[index].status, expected_status);
                            CHECK(method_client.rpcs[index].status_in_trailers);
                            if (!expected_status) {
                                CHECK_EQ(method_client.rpcs[index].response_len, size);
                                if (method_client.rpcs[index].response_len == size && size)
                                    CHECK(memcmp(method_client.rpcs[index].response.get(),
                                                 bytes,
                                                 size) == 0);
                            }
                        }
                    };
                invoke_method(0, framed, sizeof(framed), 0);
                const u8 empty[] = {0, 0, 0, 0, 0};
                invoke_method(1, empty, sizeof(empty), 0);
                invoke_method(2, empty, 0, 13);  // Empty transport is not an empty message.
                const u8 compressed[] = {1, 0, 0, 0, 0};
                invoke_method(3, compressed, sizeof(compressed), 13);
                const u8 invalid[] = {0, 0, 0, 0, 1, 128};
                invoke_method(4, invalid, sizeof(invalid), 13);
                invoke_method(5, framed, sizeof(framed), 0);
                Client enum_client;
                const bool enum_connected = enum_client.init(get_port(lfd));
                CHECK(enum_connected);
                if (enum_connected) {
                    auto invoke_enum = [&](u32 index,
                                           const u8* payload,
                                           u32 size,
                                           const u8* expected,
                                           u32 expected_size,
                                           u32 status) {
                        u8 envelope[1024]{};
                        for (u32 n = 0; n < 4; ++n)
                            envelope[n + 1] = static_cast<u8>(size >> (24 - 8 * n));
                        memcpy(envelope + 5, payload, size);
                        CHECK(enum_client.request_native_raw(index,
                                                             envelope,
                                                             size + 5,
                                                             "1H",
                                                             nullptr,
                                                             "/example.StringCodec/Echo") > 0);
                        enum_client.rpcs[index].max_chunk = 1;
                        const bool complete = enum_client.until(index, true);
                        CHECK(complete);
                        if (!complete) return;
                        CHECK_EQ(enum_client.rpcs[index].status, status);
                        CHECK(enum_client.rpcs[index].status_in_trailers);
                        CHECK_EQ(enum_client.rpcs[index].response_len,
                                 status ? 0u : expected_size + 5);
                        if (!status && enum_client.rpcs[index].response_len == expected_size + 5) {
                            const auto* response = enum_client.rpcs[index].response.get();
                            CHECK_EQ(response[0], 0u);
                            for (u32 n = 0; n < 4; ++n)
                                CHECK_EQ(response[n + 1],
                                         static_cast<u8>(expected_size >> (24 - 8 * n)));
                            CHECK(memcmp(response + 5, expected, expected_size) == 0);
                        }
                    };
                    invoke_enum(0,
                                kEnumPacked,
                                sizeof(kEnumPacked),
                                kEnumCanonical,
                                sizeof(kEnumCanonical),
                                0);
                    invoke_enum(1,
                                kEnumCanonical,
                                sizeof(kEnumCanonical),
                                kEnumCanonical,
                                sizeof(kEnumCanonical),
                                0);
                    const u8 malformed[] = {18, 3, 18, 1, 128};
                    invoke_enum(2, malformed, sizeof(malformed), nullptr, 0, 13);
                    invoke_enum(
                        3, kEnumOverElementLimit, sizeof(kEnumOverElementLimit), nullptr, 0, 13);
                    invoke_enum(4,
                                kEnumPacked,
                                sizeof(kEnumPacked),
                                kEnumCanonical,
                                sizeof(kEnumCanonical),
                                0);
                    // Stall response DATA so cancellation exercises an owned enum response,
                    // rather than cancelling a request that has not reached its handler.
                    nghttp2_settings_entry paused_window{NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 0};
                    CHECK_EQ(nghttp2_submit_settings(
                                 enum_client.session, NGHTTP2_FLAG_NONE, &paused_window, 1),
                             0);
                    const u8 empty_frame[] = {0, 0, 0, 0, 0};
                    const int32_t cancelled =
                        enum_client.request_native_raw(5,
                                                       empty_frame,
                                                       sizeof(empty_frame),
                                                       "1H",
                                                       nullptr,
                                                       "/example.StringCodec/Echo");
                    CHECK(cancelled > 0);
                    const u64 enum_deadline = monotonic_us() + 5000000;
                    while (!enum_client.rpcs[5].http_status && monotonic_us() < enum_deadline)
                        if (!enum_client.step()) break;
                    CHECK_EQ(enum_client.rpcs[5].http_status, 200u);
                    CHECK_EQ(enum_client.rpcs[5].response_len, 0u);
                    CHECK_EQ(nghttp2_submit_rst_stream(
                                 enum_client.session, NGHTTP2_FLAG_NONE, cancelled, NGHTTP2_CANCEL),
                             0);
                    nghttp2_settings_entry resumed_window{NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE,
                                                          65535};
                    CHECK_EQ(nghttp2_submit_settings(
                                 enum_client.session, NGHTTP2_FLAG_NONE, &resumed_window, 1),
                             0);
                    invoke_enum(6,
                                kEnumPacked,
                                sizeof(kEnumPacked),
                                kEnumCanonical,
                                sizeof(kEnumCanonical),
                                0);
                }
            }
        }
    }
    shard->stop();
    shard->join();
    shard->loop->force_close_all();
    CHECK_EQ(shard->shard_metrics.connections_active, 0u);
    CHECK_EQ(shard->shard_metrics.grpc_active, 0u);
    if (shard->loop->listen_fd >= 0) {
        close(shard->loop->listen_fd);
        shard->loop->listen_fd = -1;
    }
    shard->shutdown();
}
TEST(grpc_proxy, repeated_protobuf_network_epoll) {
    repeated_protobuf_network_case<EpollEventLoop>(_tc);
}
TEST(grpc_proxy, repeated_protobuf_network_iouring) {
    repeated_protobuf_network_case<IoUringEventLoop>(_tc);
}
#endif
