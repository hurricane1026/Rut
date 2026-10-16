#include "rut/runtime/callbacks_impl.h"
#include "rut/runtime/epoll_event_loop.h"
#include "rut/runtime/iouring_event_loop.h"
#include "rut/runtime/shard.h"
#include "test.h"
#include "test_helpers.h"

#include <nghttp2/nghttp2.h>
#include <openssl/ssl.h>
#if RUT_GRPC_JIT
#include "rut/serve_loader.h"
#endif
#include <atomic>
#include <memory>

#include <poll.h>
#include <pthread.h>
#include <signal.h>

using namespace rut;

namespace {
u64 grpc_jit_forward(void*, jit::HandlerCtx*, const u8*, u32, void*) {
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
            nghttp2_session_callbacks* cb;
            nghttp2_session_callbacks_new(&cb);
            nghttp2_session_callbacks_set_on_frame_recv_callback(cb, &frame);
            nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cb, &data);
            nghttp2_session* session;
            nghttp2_session_server_new(&session, cb, self);
            nghttp2_session_callbacks_del(cb);
            nghttp2_submit_settings(session, 0, nullptr, 0);
            flush_session(session, self->fd);
            while (!self->stop.load()) {
                pollfd r{self->fd, POLLIN, 0};
                if (poll(&r, 1, 20) <= 0) continue;
                u8 bytes[16384];
                const ssize_t n = recv(self->fd, bytes, sizeof(bytes), 0);
                if (n <= 0 || nghttp2_session_mem_recv(session, bytes, n) != n ||
                    !flush_session(session, self->fd))
                    break;
            }
            nghttp2_session_del(session);
            close(self->fd);
            self->fd = -1;
        }
        return nullptr;
    }
    bool start() {
        listen_fd = create_listen_socket(0).value_or(-1);
        if (listen_fd < 0) return false;
        started = pthread_create(&thread, nullptr, &run, this) == 0;
        return started;
    }
    ~EchoServer() {
        stop = true;
        if (started) pthread_join(thread, nullptr);
        if (listen_fd >= 0) close(listen_fd);
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
void streaming_case(rut::test::TestCase* _tc, bool tls = false) {
    auto server = std::make_unique<EchoServer>();
    REQUIRE(server->start());
    auto shard = std::make_unique<Shard<Loop>>();
    const int lfd = create_listen_socket(0).value_or(-1);
    REQUIRE(lfd >= 0);
    if (!shard->init(0, lfd).has_value()) {
        close(lfd);
        SKIP("backend unavailable");
    }
    RouteConfig cfg;
    REQUIRE(cfg.add_upstream("grpc", 0x7f000001, get_port(server->listen_fd)).has_value());
    cfg.upstreams[0].http2 = true;
    CHECK_EQ(cfg.upstreams[0].addr_count, 1u);
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
    if (tls) {
        char path[] = "/tmp/rut-grpc-XXXXXX";
        const int file = mkstemp(path);
        REQUIRE(file >= 0);
        char source[512];
        const int len =
            snprintf(source,
                     sizeof(source),
                     "upstream grpc { host: \"127.0.0.1\", port: %u, protocol: .http2 }\n"
                     "route POST \"/test.Echo/Call\" { return forward(grpc) }\n"
                     "route POST \"/jit.Echo/Call\" { return forward(grpc) }\n"
                     "route POST \"/jitwait.Echo/Call\" { wait(100) return forward(grpc) }\n",
                     get_port(server->listen_fd));
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
    CHECK_EQ(shard->shard_metrics.connections_total, 2u);
    shard->loop->force_close_all();
    CHECK_EQ(shard->shard_metrics.connections_active, 0u);
    CHECK_EQ(shard->shard_metrics.connections_closed, 2u);
    if (shard->loop->listen_fd >= 0) {
        close(shard->loop->listen_fd);
        shard->loop->listen_fd = -1;
    }
    shard->shutdown();
    if (tls_server) destroy_tls_server_context(tls_server);
}

struct GrpcDriveFixture {
    Connection* grpc_upstreams = nullptr;
    const RouteConfig** config_ptr = nullptr;
    TimerWheel timer;
    u32 keepalive_timeout = 60;
    u32 sends = 0;
    u32 last_send_len = 0;
    bool closed = false;
    GrpcDriveFixture() { timer.init(); }
    bool submit_send(Connection&, const u8*, u32 len) {
        sends++;
        last_send_len = len;
        return true;
    }
    bool submit_recv(Connection&) { return true; }
    bool submit_connect(Connection&, const void*, u32) { return true; }
    bool submit_send_upstream(Connection&, const u8*, u32) { return true; }
    bool submit_recv_upstream(Connection&) { return true; }
    bool alloc_upstream_buf(Connection&) { return true; }
    void clear_upstream_fd(u32) {}
    bool alloc_response_header_buf(Connection&) { return true; }
    bool schedule_yield_timer(Connection&, u32) { return true; }
    bool is_draining() const { return false; }
    void epoch_enter() {}
    void epoch_leave() {}
    void close_conn(Connection&) { closed = true; }
};
}  // namespace

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

    // The response on stream 1 has ended, but its exchange remains attached
    // while slowdown cleanup drains it.  Its sent HEADERS still count as an
    // opened peer stream until the exchange is retired, so queued RPCs wait.
    CHECK_EQ(h2.grpc.control_len, 0u);
    CHECK_EQ(h2.conn_recv_credit, 0u);
    CHECK(h2.peer_settings_seen);
    grpc_drive_upstream(&loop, upstream);
    CHECK_EQ(loop.sends, 0u);
    CHECK_FALSE(queued.request_headers_sent);
    CHECK_FALSE(newest.request_headers_sent);
    CHECK_EQ(loop.grpc_upstreams, &upstream);

    retained.response_end = true;
    grpc_drive_upstream(&loop, upstream);
    CHECK_EQ(loop.sends, 1u);
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
TEST(grpc_proxy, successful_connect_clears_consecutive_failures) {
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
    grpc_connected<EpollEventLoop>(
        loop.get(), *connected, {connected->id, 1, 0, 0, IoEventType::UpstreamConnect, 0});
    CHECK_EQ(health->fails, 0u);
    Connection* final_attempt = loop->alloc_conn();
    REQUIRE(final_attempt != nullptr);
    final_attempt->upstream_idx = 0;
    final_attempt->upstream_backend_idx = 0;
    grpc_connected<EpollEventLoop>(
        loop.get(),
        *final_attempt,
        {final_attempt->id, -ECONNREFUSED, 0, 0, IoEventType::UpstreamConnect, 0});
    CHECK_EQ(health->fails, 1u);
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
int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    return rut::test::run_all(argc, argv);
}
