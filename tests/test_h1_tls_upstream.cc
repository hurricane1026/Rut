#include "rut/runtime/callbacks_h2.h"
#include "rut/runtime/callbacks_impl.h"
#include "rut/runtime/epoll_event_loop.h"
#include "rut/runtime/iouring_event_loop.h"
#include "rut/runtime/shard.h"
#include "test.h"
#include <new>

#include <arpa/inet.h>
#include <errno.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace rut;

namespace {
struct Origin {
    SSL_CTX* context = nullptr;
    i32 fd = -1;
    u16 port = 0;
    pthread_t thread{};
    bool started = false;
    bool mtls = false;
    bool stall = false;
    bool hold_after_response = false;
    u32 stopping = 0;
    u32 requests = 0;
    u32 uploaded = 0;
    u32 headers = 0;
    u32 response_started = 0;
    u32 body_size = 256 * 1024;
    char request[1024]{};
    bool start() {
        context = SSL_CTX_new(TLS_server_method());
        if (!context ||
            SSL_CTX_use_certificate_chain_file(context, RUT_TLS_FIXTURES "/localhost_cert.pem") !=
                1 ||
            SSL_CTX_use_PrivateKey_file(
                context, RUT_TLS_FIXTURES "/localhost_key.pem", SSL_FILETYPE_PEM) != 1)
            return false;
        if (mtls) {
            if (SSL_CTX_load_verify_locations(
                    context, RUT_TLS_FIXTURES "/localhost_cert.pem", nullptr) != 1)
                return false;
            SSL_CTX_set_verify(context, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
        }
        fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (fd < 0 || bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 ||
            listen(fd, 8) != 0)
            return false;
        socklen_t n = sizeof(addr);
        if (getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &n) != 0) return false;
        port = ntohs(addr.sin_port);
        started = pthread_create(&thread, nullptr, run, this) == 0;
        return started;
    }
    static void* run(void* arg) {
        auto& s = *static_cast<Origin*>(arg);
        while (!__atomic_load_n(&s.stopping, __ATOMIC_ACQUIRE)) {
            pollfd event{s.fd, POLLIN, 0};
            if (poll(&event, 1, 20) <= 0) continue;
            const i32 client = accept(s.fd, nullptr, nullptr);
            if (client < 0) continue;
            timeval timeout{2, 0};
            setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
            setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
            SSL* ssl = SSL_new(s.context);
            if (ssl && SSL_set_fd(ssl, client) == 1 && SSL_accept(ssl) == 1) {
                u32 used = 0;
                while (used < sizeof(s.request) - 1) {
                    const i32 n = SSL_read(
                        ssl, s.request + used, static_cast<int>(sizeof(s.request) - 1 - used));
                    if (n <= 0) break;
                    used += static_cast<u32>(n);
                    s.request[used] = 0;
                    if (strstr(s.request, "\r\n\r\n")) break;
                }
                if (const char* end = strstr(s.request, "\r\n\r\n")) {
                    __atomic_fetch_add(&s.headers, 1u, __ATOMIC_RELEASE);
                    if (const char* length = strstr(s.request, "Content-Length: ")) {
                        u32 expected = 0;
                        for (length += 16; *length >= '0' && *length <= '9'; ++length)
                            expected = expected * 10 + static_cast<u32>(*length - '0');
                        u32 received = used - static_cast<u32>(end + 4 - s.request);
                        char input[4096];
                        while (received < expected) {
                            const i32 n = SSL_read(ssl, input, sizeof(input));
                            if (n <= 0) break;
                            received += static_cast<u32>(n);
                        }
                        __atomic_store_n(&s.uploaded, received, __ATOMIC_RELEASE);
                    }
                    __atomic_fetch_add(&s.requests, 1u, __ATOMIC_RELEASE);
                    if (!s.stall) {
                        char header[128];
                        const i32 length = snprintf(header,
                                                    sizeof(header),
                                                    "HTTP/1.1 200 OK\r\nContent-Length: %u\r\n"
                                                    "Connection: %s\r\n\r\n",
                                                    s.body_size,
                                                    s.hold_after_response ? "keep-alive" : "close");
                        if (SSL_write(ssl, header, length) > 0) {
                            char body[16384];
                            memset(body, 'x', sizeof(body));
                            for (u32 offset = 0; offset < s.body_size;) {
                                const u32 n = s.body_size - offset < sizeof(body)
                                                  ? s.body_size - offset
                                                  : sizeof(body);
                                const i32 written = SSL_write(ssl, body, static_cast<int>(n));
                                if (written <= 0) break;
                                offset += static_cast<u32>(written);
                                __atomic_store_n(&s.response_started, 1u, __ATOMIC_RELEASE);
                            }
                            if (s.hold_after_response) {
                                while (!__atomic_load_n(&s.stopping, __ATOMIC_ACQUIRE)) usleep(1000);
                            } else {
                                (void)SSL_shutdown(ssl);
                            }
                        }
                    } else {
                        while (!__atomic_load_n(&s.stopping, __ATOMIC_ACQUIRE)) {
                            pollfd wait{client, POLLIN, 0};
                            if (poll(&wait, 1, 20) > 0) break;
                        }
                    }
                }
            }
            if (ssl) SSL_free(ssl);
            close(client);
        }
        return nullptr;
    }
    ~Origin() {
        __atomic_store_n(&stopping, 1u, __ATOMIC_RELEASE);
        if (started) pthread_join(thread, nullptr);
        if (fd >= 0) close(fd);
        if (context) SSL_CTX_free(context);
    }
};

template <typename T>
struct Mapped {
    T* value = nullptr;
    Mapped() {
        void* region =
            mmap(nullptr, sizeof(T), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (region != MAP_FAILED) {
            value = static_cast<T*>(region);
            ::new (value) T{};
        }
    }
    ~Mapped() {
        if (value) {
            value->~T();
            munmap(value, sizeof(T));
        }
    }
};

u16 socket_port(i32 fd) {
    sockaddr_in addr{};
    socklen_t n = sizeof(addr);
    return getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &n) == 0 ? ntohs(addr.sin_port) : 0;
}

template <typename Loop>
void exercise(rut::test::TestCase* _tc,
              bool bad_name = false,
              bool mtls = false,
              bool downstream_tls = false,
              bool cancel = false,
              u32 upload = 0,
              bool invalid_ca = false,
              bool response_timeout = false,
              bool hold_after_response = false,
              bool slow_client = false) {
    signal(SIGPIPE, SIG_IGN);
    Origin origin;
    origin.mtls = mtls;
    origin.stall = cancel || response_timeout;
    origin.hold_after_response = hold_after_response;
    if (hold_after_response) origin.body_size = 16384;
    if (slow_client) origin.body_size = 2 * 1024 * 1024;
    REQUIRE(origin.start());
    Mapped<Shard<Loop>> shard;
    Mapped<RouteConfig> cfg;
    REQUIRE(shard.value && cfg.value);
    const i32 listener = create_listen_socket(0).value_or(-1);
    REQUIRE(listener >= 0);
    if (slow_client) {
        int send_buffer = 4096;
        setsockopt(listener, SOL_SOCKET, SO_SNDBUF, &send_buffer, sizeof(send_buffer));
    }
    if (!shard.value->init(0, listener).has_value()) {
        close(listener);
        SKIP("backend unavailable");
    }
    REQUIRE(cfg.value->add_upstream("origin", 0x7f000001, origin.port).has_value());
    auto& spec = cfg.value->upstreams[0].tls;
    spec.enabled = true;
    snprintf(
        spec.ca,
        sizeof(spec.ca),
        "%s",
        invalid_ca ? "/nonexistent/rut-upstream-ca.pem" : RUT_TLS_FIXTURES "/localhost_cert.pem");
    snprintf(
        spec.server_name, sizeof(spec.server_name), "%s", bad_name ? "wrong.example" : "localhost");
    if (mtls) {
        snprintf(spec.cert, sizeof(spec.cert), "%s", RUT_TLS_FIXTURES "/localhost_cert.pem");
        snprintf(spec.key, sizeof(spec.key), "%s", RUT_TLS_FIXTURES "/localhost_key.pem");
    }
    REQUIRE(cfg.value->add_proxy("/", upload ? 'P' : 'G', 0));
    shard.value->route_config = cfg.value;
    if (response_timeout) shard.value->loop->upstream_timeout = 1;
    TlsServerContext* inbound = nullptr;
    if (downstream_tls) {
        auto context = create_tls_server_context(RUT_TLS_FIXTURES "/localhost_cert.pem",
                                                 RUT_TLS_FIXTURES "/localhost_key.pem");
        REQUIRE(context.has_value());
        inbound = context.value();
        shard.value->loop->tls_server = inbound;
    }
    REQUIRE(shard.value->spawn(-1).has_value());
    const i32 client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (slow_client && client >= 0) {
        int receive_buffer = 4096;
        setsockopt(client, SOL_SOCKET, SO_RCVBUF, &receive_buffer, sizeof(receive_buffer));
    }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(socket_port(listener));
    const bool connected =
        client >= 0 && connect(client, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0;
    CHECK(connected);
    timeval timeout{5, 0};
    setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    SSL_CTX* client_context = nullptr;
    SSL* ssl = nullptr;
    if (downstream_tls && connected) {
        client_context = SSL_CTX_new(TLS_client_method());
        ssl = SSL_new(client_context);
        CHECK(SSL_set_fd(ssl, client) == 1 && SSL_connect(ssl) == 1);
    }
    constexpr char request[] =
        "GET /hello?query=yes HTTP/1.1\r\nHost: example\r\nConnection: close\r\n\r\n";
    if (connected) {
        char post[160];
        const i32 post_length =
            snprintf(post,
                     sizeof(post),
                     "POST /hello?query=yes HTTP/1.1\r\nHost: example\r\nContent-Length: "
                     "%u\r\nConnection: close\r\n\r\n",
                     upload);
        const char* header = upload ? post : request;
        const u32 length = upload ? static_cast<u32>(post_length) : sizeof(request) - 1;
        CHECK((ssl ? SSL_write(ssl, header, static_cast<int>(length))
                   : send(client, header, length, MSG_NOSIGNAL)) > 0);
        if (hold_after_response) {
            for (u32 i = 0; i < 500 && !__atomic_load_n(&origin.response_started, __ATOMIC_ACQUIRE);
                 ++i)
                usleep(1000);
            CHECK_EQ(__atomic_load_n(&origin.response_started, __ATOMIC_ACQUIRE), 1u);
        }
        if (slow_client) {
            for (u32 i = 0; i < 500 && !__atomic_load_n(&origin.response_started, __ATOMIC_ACQUIRE);
                 ++i)
                usleep(1000);
            CHECK_EQ(__atomic_load_n(&origin.response_started, __ATOMIC_ACQUIRE), 1u);
            usleep(100000);
        }
        if (upload) {
            // Deliberately exercise streaming after header admission; request
            // admission overflow is covered by the existing HTTP tests.
            for (u32 i = 0; i < 200 && __atomic_load_n(&origin.headers, __ATOMIC_ACQUIRE) == 0; ++i)
                usleep(10000);
            CHECK_EQ(__atomic_load_n(&origin.headers, __ATOMIC_ACQUIRE), 1u);
        }
        char body[4096];
        memset(body, 'b', sizeof(body));
        for (u32 sent = 0; sent < upload;) {
            const u32 n = upload - sent < sizeof(body) ? upload - sent : sizeof(body);
            const auto written = ssl ? SSL_write(ssl, body, static_cast<int>(n))
                                     : send(client, body, n, MSG_NOSIGNAL);
            if (written <= 0) {
                CHECK(false);
                break;
            }
            sent += static_cast<u32>(written);
            usleep(2000);  // Stream beyond one receive slice without overflowing request admission.
        }
    }
    if (cancel) {
        for (u32 i = 0; i < 200 && __atomic_load_n(&origin.requests, __ATOMIC_ACQUIRE) == 0; i++)
            usleep(10000);
        CHECK_EQ(__atomic_load_n(&origin.requests, __ATOMIC_ACQUIRE), 1u);
    } else {
        char block[8192];
        char prefix[512]{};
        u32 total = 0;
        bool body_valid = true;
        for (;;) {
            const auto n =
                ssl ? SSL_read(ssl, block, sizeof(block)) : recv(client, block, sizeof(block), 0);
            if (n <= 0) break;
            const u32 room =
                sizeof(prefix) - 1 - (total < sizeof(prefix) - 1 ? total : sizeof(prefix) - 1);
            const u32 take = static_cast<u32>(n) < room ? static_cast<u32>(n) : room;
            if (take) memcpy(prefix + total, block, take);
            if (const char* start = strstr(prefix, "\r\n\r\n")) {
                const u32 offset = static_cast<u32>(start + 4 - prefix);
                for (u32 i = total < offset ? offset - total : 0; i < static_cast<u32>(n); ++i)
                    if (block[i] != 'x') body_valid = false;
            }
            total += static_cast<u32>(n);
            if (hold_after_response) {
                const char* response_body = strstr(prefix, "\r\n\r\n");
                if (response_body && total >= static_cast<u32>(response_body + 4 - prefix) +
                                                  origin.body_size)
                    break;
            }
        }
        if (bad_name || invalid_ca) {
            CHECK(strstr(prefix, " 502 ") || strstr(prefix, " 503 "));
            CHECK_EQ(__atomic_load_n(&origin.requests, __ATOMIC_ACQUIRE), 0u);
        } else if (response_timeout) {
            CHECK(strstr(prefix, " 504 "));
        } else {
            CHECK(strstr(prefix, " 200 "));
            CHECK(body_valid);
            const char* body = strstr(prefix, "\r\n\r\n");
            CHECK(body);
            if (body) {
                if (total - static_cast<u32>(body + 4 - prefix) != origin.body_size)
                    fprintf(stderr,
                            "body bytes: %u expected %u prefix %.90s\n",
                            total - static_cast<u32>(body + 4 - prefix),
                            origin.body_size,
                            prefix);
                CHECK_EQ(total - static_cast<u32>(body + 4 - prefix), origin.body_size);
            }
            CHECK(strstr(
                origin.request,
                upload ? "POST /hello?query=yes HTTP/1.1" : "GET /hello?query=yes HTTP/1.1"));
            CHECK_EQ(__atomic_load_n(&origin.uploaded, __ATOMIC_ACQUIRE), upload);
        }
    }
    if (ssl) SSL_free(ssl);
    if (client_context) SSL_CTX_free(client_context);
    if (client >= 0) close(client);
    shard.value->stop();
    shard.value->join();
    shard.value->loop->force_close_all();
    if constexpr (requires { shard.value->loop->backend.failure_code(); }) {
        auto& loop = *shard.value->loop;
        IoEvent events[64];
        for (u32 attempt = 0; attempt < 100 && loop.free_top < loop.connection_capacity;
             ++attempt) {
            const u32 count =
                loop.backend.wait(events, 64, loop.conns, loop.slots_initialized, false);
            for (u32 i = 0; i < count; ++i) loop.dispatch(events[i]);
            loop.reclaim_pending();
            usleep(1000);
        }
        for (u32 i = 0; i < loop.slots_initialized; ++i)
            if (loop.conns[i].pending_ops)
                fprintf(stderr,
                        "retained conn %u pending %u fd %d upstream %d\n",
                        i,
                        loop.conns[i].pending_ops,
                        loop.conns[i].fd,
                        loop.conns[i].upstream_fd);
    }
    // Both the accepted client and dedicated TLS transport must be retired.
    CHECK_EQ(shard.value->loop->free_top, shard.value->loop->connection_capacity);
    if (inbound) {
        shard.value->loop->tls_server = nullptr;
        destroy_tls_server_context(inbound);
    }
}
}  // namespace

TEST(h1_tls_upstream, epoll_large_response) {
    exercise<EpollEventLoop>(_tc);
}
TEST(h1_tls_upstream, iouring_large_response) {
    exercise<IoUringEventLoop>(_tc);
}
TEST(h1_tls_upstream, iouring_keepalive_response_has_no_followup_origin_read) {
    exercise<IoUringEventLoop>(_tc, false, false, false, false, 0, false, false, true);
}
TEST(h1_tls_upstream, epoll_slow_client_drains_large_response_after_upstream_fin) {
    exercise<EpollEventLoop>(_tc, false, false, false, false, 0, false, false, false, true);
}
TEST(h1_tls_upstream, epoll_verify_name_before_request) {
    exercise<EpollEventLoop>(_tc, true);
}
TEST(h1_tls_upstream, iouring_verify_name_before_request) {
    exercise<IoUringEventLoop>(_tc, true);
}
TEST(h1_tls_upstream, epoll_mtls) {
    exercise<EpollEventLoop>(_tc, false, true);
}
TEST(h1_tls_upstream, iouring_mtls) {
    exercise<IoUringEventLoop>(_tc, false, true);
}
TEST(h1_tls_upstream, epoll_tls_downstream) {
    exercise<EpollEventLoop>(_tc, false, false, true);
}
TEST(h1_tls_upstream, iouring_tls_downstream) {
    exercise<IoUringEventLoop>(_tc, false, false, true);
}
TEST(h1_tls_upstream, epoll_cancel) {
    exercise<EpollEventLoop>(_tc, false, false, false, true);
}
TEST(h1_tls_upstream, iouring_cancel) {
    exercise<IoUringEventLoop>(_tc, false, false, false, true);
}

TEST(h1_tls_upstream, epoll_post_upload) {
    exercise<EpollEventLoop>(_tc, false, false, false, false, 48000);
}
TEST(h1_tls_upstream, iouring_post_upload) {
    exercise<IoUringEventLoop>(_tc, false, false, false, false, 48000);
}
TEST(h1_tls_upstream, epoll_bad_ca) {
    exercise<EpollEventLoop>(_tc, false, false, false, false, 0, true);
}
TEST(h1_tls_upstream, iouring_bad_ca) {
    exercise<IoUringEventLoop>(_tc, false, false, false, false, 0, true);
}

TEST(h1_tls_upstream, epoll_response_timeout) {
    exercise<EpollEventLoop>(_tc, false, false, false, false, 0, false, true);
}
TEST(h1_tls_upstream, iouring_response_timeout) {
    exercise<IoUringEventLoop>(_tc, false, false, false, false, 0, false, true);
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
