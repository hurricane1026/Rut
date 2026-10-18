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
        bool trailer;
        u8 data[65535];
    } streams[64]{};
    int listen_fd = -1;
    int fd = -1;
    pthread_t thread{};
    std::atomic<bool> stop{false};
    std::atomic<u32> requests{0};
    std::atomic<u32> resets{0};
    std::atomic<u32> accepts{0};
    std::atomic<u32> reply_mode{0};
    std::atomic<u32> request_trailers{0};
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
        if (!n && !s->end) return NGHTTP2_ERR_DEFERRED;
        memcpy(buf, s->data, n);
        s->len -= n;
        memmove(s->data, s->data + n, s->len);
        if (!s->len && s->end) {
            *flags |= NGHTTP2_DATA_FLAG_EOF | NGHTTP2_DATA_FLAG_NO_END_STREAM;
            nghttp2_nv trailers[] = {nv("grpc-status", "0"), nv("x-trailer", "present")};
            if (nghttp2_submit_trailer(session, id, trailers, 2) != 0)
                return NGHTTP2_ERR_CALLBACK_FAILURE;
            s->trailer = true;
        }
        return n;
    }
    static int frame(nghttp2_session* session, const nghttp2_frame* f, void* user) {
        auto* self = static_cast<EchoServer*>(user);
        if (!f->hd.stream_id) return 0;
        auto* s = self->get(f->hd.stream_id);
        if (!s) return NGHTTP2_ERR_CALLBACK_FAILURE;
        if (f->hd.type == NGHTTP2_HEADERS && f->headers.cat == NGHTTP2_HCAT_REQUEST) {
            self->requests++;
            const u32 mode = self->reply_mode.exchange(0);
            if (mode == 2) return NGHTTP2_ERR_CALLBACK_FAILURE;
            if (mode == 1) {
                nghttp2_nv error[] = {nv(":status", "200"),
                                      nv("content-type", "application/grpc"),
                                      nv("grpc-status", "7"),
                                      nv("grpc-message", "denied")};
                return nghttp2_submit_response(session, s->id, error, 4, nullptr);
            }
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
            nghttp2_nv headers[] = {nv(":status", "200"),
                                    nv("content-type", "application/grpc"),
                                    nv("x-meta-bin", "AAEC/w==")};
            nghttp2_data_provider provider{};
            provider.source.ptr = s;
            provider.read_callback = &read_data;
            if (nghttp2_submit_response(session, s->id, headers, 3, &provider) != 0)
                return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        if (f->hd.type == NGHTTP2_RST_STREAM) self->resets++;
        if (f->hd.type == NGHTTP2_HEADERS && f->headers.cat == NGHTTP2_HCAT_HEADERS)
            self->request_trailers++;
        if ((f->hd.type == NGHTTP2_HEADERS || f->hd.type == NGHTTP2_DATA) &&
            (f->hd.flags & NGHTTP2_FLAG_END_STREAM)) {
            s->end = true;
            nghttp2_session_resume_data(session, s->id);
        }
        return 0;
    }
    static int header(nghttp2_session*,
                      const nghttp2_frame*,
                      const uint8_t* name,
                      size_t name_len,
                      const uint8_t* value,
                      size_t value_len,
                      uint8_t,
                      void* user) {
        if (name_len != 7 || memcmp(name, ":scheme", 7) != 0) return 0;
        auto* server = static_cast<EchoServer*>(user);
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
    bool start(bool tls = false, bool mutual = false, bool h2 = true) {
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
        listen_fd = create_listen_socket(0).value_or(-1);
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
        u32 sent = 0, received = 0, size = 0;
        u32 status = 99;
        bool request_trailer = false, end = true, response_end = false, closed = false, ok = false,
             meta = false, trailer = false;
    } rpcs[17];
    nghttp2_session* session = nullptr;
    bool goaway = false;
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
        u32 n = rpc->size - rpc->sent;
        if (n > cap) n = static_cast<u32>(cap);
        if (!n && !rpc->end) return NGHTTP2_ERR_DEFERRED;
        for (u32 i = 0; i < n; i++) out[i] = byte_at(rpc->sent + i);
        rpc->sent += n;
        if (rpc->sent == rpc->size && rpc->end) {
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
        for (u32 i = 0; i < len; i++)
            if (data[i] != byte_at(rpc.received + i)) return NGHTTP2_ERR_CALLBACK_FAILURE;
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
        if (n == 11 && memcmp(name, "grpc-status", n) == 0) {
            rpc.ok = v == 1 && *value == '0';
            rpc.status = 0;
            for (size_t i = 0; i < v; i++) rpc.status = rpc.status * 10 + value[i] - '0';
        }
        if (n == 10 && memcmp(name, "x-meta-bin", n) == 0)
            rpc.meta = v == 8 && memcmp(value, "AAEC/w==", 8) == 0;
        if (n == 9 && memcmp(name, "x-trailer", n) == 0)
            rpc.trailer = v == 7 && memcmp(value, "present", 7) == 0;
        return 0;
    }
    static int frame(nghttp2_session*, const nghttp2_frame* f, void* ctx) {
        if (f->hd.type == NGHTTP2_GOAWAY) static_cast<Client*>(ctx)->goaway = true;
        if ((f->hd.type == NGHTTP2_HEADERS || f->hd.type == NGHTTP2_DATA) &&
            (f->hd.flags & NGHTTP2_FLAG_END_STREAM))
            static_cast<Client*>(ctx)->rpcs[(f->hd.stream_id - 1) / 2].response_end = true;
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
                    bool mutual = false) {
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
            CHECK_EQ(a.request(0, 128, false), 1);
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
                a.rpcs[0].size = 100000;
                a.rpcs[0].end = true;
                CHECK_EQ(nghttp2_session_resume_data(a.session, 1), 0);
                CHECK(a.until(0, true));
                CHECK(a.rpcs[0].ok && a.rpcs[0].trailer);
                CHECK_EQ(a.rpcs[0].received, 100000u);
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
        return true;
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
void pending_send(void*, Connection&, IoEvent) {}
}  // namespace

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
    queued.request_headers_len = newest.request_headers_len = 1;
    queued.request_headers[0] = newest.request_headers[0] = 0;
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
    bool submit_connect(Connection&, const void*, u32) { return false; }
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
    CHECK_EQ(loop.grpc_upstreams, nullptr);
    CHECK_EQ(health->fails, 0u);
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
    u8 send_bytes[] = {0};
    conn.send_buf.bind(send_bytes, sizeof(send_bytes));
    conn.send_buf.commit(1);
    grpc_on_upstream_sent<GrpcDriveFixture>(&loop, conn, {conn.id, 1, 0, 0, IoEventType::Send, 0});
    CHECK(loop.closed);
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

TEST(grpc_proxy, streaming_and_pooling_epoll) {
    streaming_case<EpollEventLoop>(_tc);
}
TEST(grpc_proxy, streaming_and_pooling_iouring) {
    streaming_case<IoUringEventLoop>(_tc);
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
