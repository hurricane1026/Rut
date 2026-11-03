#include "rs256_fixture.h"
#include "rut/runtime/https_fetch.h"
#include "rut/runtime/rs256_policy.h"
#include "test.h"

#include <arpa/inet.h>
#include <errno.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace rut;

static Str text(const char* value) {
    return {value, static_cast<u32>(strlen(value))};
}

struct TlsOrigin {
    SSL_CTX* context = nullptr;
    int listener = -1;
    u16 port = 0;
    pthread_t thread{};
    bool started = false;
    u32 stop = 0;
    u32 served = 0;
    Str responses[8]{};
    u32 count = 0;
    u32 fragment = 16384;
    bool clean_close = true;
    char request[2048]{};
    bool init() {
        context = SSL_CTX_new(TLS_server_method());
        if (!context ||
            SSL_CTX_use_certificate_chain_file(context, RUT_TESTDATA_DIR "/localhost_cert.pem") !=
                1 ||
            SSL_CTX_use_PrivateKey_file(
                context, RUT_TESTDATA_DIR "/localhost_key.pem", SSL_FILETYPE_PEM) != 1)
            return false;
        listener = socket(AF_INET, SOCK_STREAM, 0);
        if (listener < 0) return false;
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 ||
            listen(listener, 8) != 0)
            return false;
        socklen_t length = sizeof(address);
        if (getsockname(listener, reinterpret_cast<sockaddr*>(&address), &length) != 0)
            return false;
        port = ntohs(address.sin_port);
        started = pthread_create(&thread, nullptr, run, this) == 0;
        return started;
    }
    static void* run(void* pointer) {
        auto& self = *static_cast<TlsOrigin*>(pointer);
        while (!__atomic_load_n(&self.stop, __ATOMIC_ACQUIRE)) {
            pollfd ready{self.listener, POLLIN, 0};
            if (poll(&ready, 1, 10) <= 0) continue;
            const int fd = accept(self.listener, nullptr, nullptr);
            if (fd < 0) continue;
            timeval timeout{2, 0};
            (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
            (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
            SSL* ssl = SSL_new(self.context);
            if (ssl && SSL_set_fd(ssl, fd) == 1 && SSL_accept(ssl) == 1) {
                u32 length = 0;
                self.request[0] = 0;
                while (length < sizeof(self.request) - 1) {
                    const int n =
                        SSL_read(ssl, self.request + length, sizeof(self.request) - 1 - length);
                    if (n <= 0) break;
                    length += static_cast<u32>(n);
                    self.request[length] = 0;
                    if (strstr(self.request, "\r\n\r\n")) break;
                }
                const u32 index = __atomic_fetch_add(&self.served, 1u, __ATOMIC_ACQ_REL);
                const Str response = self.responses[index < self.count ? index : self.count - 1];
                for (u32 offset = 0; offset < response.len;) {
                    const u32 remaining = response.len - offset;
                    const u32 size = remaining < self.fragment ? remaining : self.fragment;
                    const int n = SSL_write(ssl, response.ptr + offset, size);
                    if (n <= 0) break;
                    offset += static_cast<u32>(n);
                }
                if (self.clean_close) (void)SSL_shutdown(ssl);
            }
            SSL_free(ssl);
            close(fd);
        }
        return nullptr;
    }
    HttpsEndpoint endpoint() const {
        HttpsEndpoint result{};
        strcpy(result.address, "127.0.0.1");
        strcpy(result.path, "/keys?profile=rs256");
        result.port = port;
        result.tls.enabled = true;
        strcpy(result.tls.server_name, "localhost");
        strcpy(result.tls.ca, RUT_TESTDATA_DIR "/localhost_cert.pem");
        return result;
    }
    ~TlsOrigin() {
        __atomic_store_n(&stop, 1u, __ATOMIC_RELEASE);
        if (started) pthread_join(thread, nullptr);
        if (listener >= 0) close(listener);
        SSL_CTX_free(context);
    }
};

TEST(https_fetch, bounded_json_response_framing_fragmentation_and_limits) {
    const char* valid[] = {
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
        ("HTTP/1.1 200 OK\r\nContent-Type: application/jwk-set+json; "
         "charset=utf-8\r\nTransfer-Encoding: chunked\r\n\r\n1\r\n{\r\n1\r\n}\r\n0\r\n\r\n"),
        "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{}",
    };
    for (const char* response : valid) {
        for (u32 fragment = 1; fragment < 12; ++fragment) {
            BoundedJsonResponse parser;
            parser.reset();
            const u32 length = static_cast<u32>(strlen(response));
            for (u32 offset = 0; offset < length;) {
                const u32 size = length - offset < fragment ? length - offset : fragment;
                CHECK(parser.append({response + offset, size}) !=
                      BoundedJsonResponse::Result::Error);
                offset += size;
            }
            CHECK_EQ(parser.finish(), BoundedJsonResponse::Result::Complete);
            CHECK(parser.body().eq(lit_str("{}")));
        }
    }
    const char* invalid[] = {
        "HTTP/1.1 302 Found\r\nLocation: https://elsewhere/keys\r\nContent-Type: "
        "application/json\r\nContent-Length: 2\r\n\r\n{}",
        "HTTP/1.1 304 Not Modified\r\nContent-Type: application/json\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}",
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 2\r\n\r\n{}",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Type: "
        "application/json\r\nContent-Length: 2\r\n\r\n{}",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: "
        "gzip\r\nContent-Length: 2\r\n\r\n{}",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nContent-Length: "
        "2\r\n\r\n{}",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
        "2\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: gzip, "
        "chunked\r\n\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 8193\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}extra",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: "
        "chunked\r\n\r\n3\r\n{}\r\n0\r\n\r\n",
    };
    for (const char* response : invalid) {
        BoundedJsonResponse parser;
        parser.reset();
        (void)parser.append(text(response));
        CHECK_EQ(parser.finish(), BoundedJsonResponse::Result::Error);
        CHECK(parser.body().ptr == nullptr);
    }
    BoundedJsonResponse parser;
    parser.reset();
    char too_large[BoundedJsonResponse::kMaxWire + 1]{};
    CHECK_EQ(parser.append({too_large, sizeof(too_large)}), BoundedJsonResponse::Result::Error);
}

TEST(https_fetch, authenticated_tls_fetch_and_wrong_hostname_rejection) {
    const char* response =
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
        "11\r\n\r\n{\"keys\":[]}";
    TlsOrigin origin;
    origin.responses[0] = text(response);
    origin.count = 1;
    origin.fragment = 7;
    REQUIRE(origin.init());
    HttpsFetch fetch;
    REQUIRE(fetch.init(origin.endpoint()));
    const u64 now = jwt_monotonic_ms();
    REQUIRE(fetch.start(now, 5000));
    for (u32 i = 0; i < 5000 && fetch.state() == HttpsFetch::State::Busy; ++i) {
        ERR_raise(ERR_LIB_USER, 1);
        fetch.advance(jwt_monotonic_ms());
        usleep(1000);
    }
    REQUIRE_EQ(fetch.state(), HttpsFetch::State::Done);
    CHECK(fetch.body().eq(lit_str("{\"keys\":[]}")));
    fetch.cancel();
    CHECK(fetch.body().ptr == nullptr);
    CHECK(!fetch.start(0, 1000));
    auto endpoint = origin.endpoint();
    strcpy(endpoint.tls.server_name, "wrong.example");
    HttpsFetch wrong;
    REQUIRE(wrong.init(endpoint));
    REQUIRE(wrong.start(jwt_monotonic_ms(), 5000));
    for (u32 i = 0; i < 5000 && wrong.state() == HttpsFetch::State::Busy; ++i) {
        wrong.advance(jwt_monotonic_ms());
        usleep(1000);
    }
    CHECK_EQ(wrong.state(), HttpsFetch::State::Failed);
    CHECK(wrong.body().ptr == nullptr);
}

TEST(https_fetch, cancellation_timeout_clock_failure_and_endpoint_validation) {
    TlsOrigin origin;
    origin.responses[0] = lit_str("HTTP/1.1 500 Error\r\n\r\n");
    origin.count = 1;
    REQUIRE(origin.init());
    HttpsFetch fetch;
    REQUIRE(fetch.init(origin.endpoint()));
    REQUIRE(fetch.start(100, 1000));
    CHECK(!fetch.start(100, 1000));
    fetch.cancel();
    CHECK_EQ(fetch.state(), HttpsFetch::State::Cancelled);
    CHECK(fetch.body().ptr == nullptr);
    REQUIRE(fetch.start(100, 1000));
    fetch.advance(1100);
    CHECK_EQ(fetch.state(), HttpsFetch::State::Failed);
    REQUIRE(fetch.start(100, 1000));
    fetch.advance(99);
    CHECK_EQ(fetch.state(), HttpsFetch::State::Failed);
    REQUIRE(fetch.start(100, 1000));
    fetch.advance(0);
    CHECK_EQ(fetch.state(), HttpsFetch::State::Failed);
    auto bad = origin.endpoint();
    strcpy(bad.path, "/keys\r\nX: injected");
    CHECK(!bad.valid());
    bad = origin.endpoint();
    strcpy(bad.address, "hostname");
    CHECK(!bad.valid());
    bad = origin.endpoint();
    strcpy(bad.tls.ca, "/missing/ca.pem");
    HttpsFetch no_ca;
    CHECK(!no_ca.init(bad));
}

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    if (argc == 2 && strcmp(argv[1], "--fixture") == 0) {
        test::Rs256Fixture first, second;
        if (!first.init() || !second.init()) return 2;
        char a_bytes[4096], b_bytes[4096];
        const Str a = first.sign(test::Rs256Fixture::header, test::Rs256Fixture::claims, a_bytes);
        const Str b = second.sign(test::Rs256Fixture::header, test::Rs256Fixture::claims, b_bytes);
        if (!a.len || !b.len) return 2;
        printf("{\"first\":%.*s,\"second\":%.*s,\"a\":\"%.*s\",\"b\":\"%.*s\"}\n",
               first.policy.len,
               first.policy.ptr,
               second.policy.len,
               second.policy.ptr,
               a.len,
               a.ptr,
               b.len,
               b.ptr);
        return 0;
    }
    return rut::test::run_all(argc, argv);
}

static Str json_response(Str body, char* output, u32 capacity) {
    const int size = snprintf(
        output,
        capacity,
        "HTTP/1.1 200 OK\r\nContent-Type: application/jwk-set+json\r\nContent-Length: %u\r\n\r\n",
        body.len);
    if (size <= 0 || static_cast<u32>(size) > capacity ||
        body.len > capacity - static_cast<u32>(size))
        return {};
    memcpy(output + size, body.ptr, body.len);
    return {output, static_cast<u32>(size) + body.len};
}

static Str fixture_jwks(test::Rs256Fixture& fixture, json::Document& document) {
    if (!document.parse(fixture.policy)) return {};
    for (u32 n = document.nodes[0].child; n != json::kNone; n = document.nodes[n].next) {
        json::Writer name{document.scratch};
        if (!document.string(document.nodes[n].key, name)) return {};
        if (Str{document.scratch, name.len}.eq(lit_str("jwks"))) return document.raw(n);
    }
    return {};
}

TEST(https_fetch, remote_jwks_rotation_failure_expiry_empty_set_and_shard_isolation) {
    test::Rs256Fixture first, second;
    REQUIRE(first.init());
    REQUIRE(second.init());
    json::Document document;
    char good[8192], rotated[8192], malformed[8192], empty[8192];
    const Str original = json_response(fixture_jwks(first, document), good, sizeof(good));
    const Str replacement = json_response(fixture_jwks(second, document), rotated, sizeof(rotated));
    REQUIRE(original.len && replacement.len);
    TlsOrigin origin;
    origin.count = 7;
    origin.responses[0] = original;
    origin.responses[1] = lit_str("HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\n\r\n");
    origin.responses[2] = json_response(lit_str("{bad"), malformed, sizeof(malformed));
    origin.responses[3] = original;
    origin.responses[4] = json_response(lit_str("{\"keys\":[]}"), empty, sizeof(empty));
    origin.responses[5] = replacement;
    origin.responses[6] = replacement;
    REQUIRE(origin.init());
    char configuration[8192];
    const int size = snprintf(
        configuration,
        sizeof(configuration),
        "%.*s,\"remoteJwks\":{\"address\":\"127.0.0.1\",\"port\":%u,\"serverName\":\"localhost\","
        "\"ca\":\"%s\",\"path\":\"/"
        "keys\",\"refreshSeconds\":1,\"maxAgeSeconds\":2,\"timeoutSeconds\":5}}",
        first.policy.len - 1,
        first.policy.ptr,
        origin.port,
        RUT_TESTDATA_DIR "/localhost_cert.pem");
    REQUIRE(size > 0 && static_cast<u32>(size) < sizeof(configuration));
    const Str policy{configuration, static_cast<u32>(size)};
    Rs256Policies policies;
    REQUIRE(policies.load(&policy, 1));
    REQUIRE(policies.activate(0));
    REQUIRE(policies.activate(1));
    char a_bytes[4096], b_bytes[4096], payload[8192];
    const Str a = first.sign(test::Rs256Fixture::header, test::Rs256Fixture::claims, a_bytes);
    const Str b = second.sign(test::Rs256Fixture::header, test::Rs256Fixture::claims, b_bytes);
    REQUIRE(a.len && b.len);
    u32 length = 7;
    const auto verify = [&](u32 shard, Str token, u64 now) {
        return policies.verify(
            shard, policy, document, token, 100, payload, sizeof(payload), length, now);
    };
    CHECK(!verify(0, a, 100));  // Bootstrap is not an offline remote cache.
    CHECK_EQ(length, 0u);
    const auto refresh = [&](u32 shard, u64 now, u32 expected_requests) {
        u32 completed = 0;
        for (u32 i = 0; i < 3000; ++i) {
            policies.maintain(shard, now);
            if (__atomic_load_n(&origin.served, __ATOMIC_ACQUIRE) >= expected_requests &&
                ++completed == 100)
                return true;
            usleep(1000);
        }
        return false;
    };
    REQUIRE(refresh(0, 100, 1));
    REQUIRE(verify(0, a, 100));
    CHECK(!verify(1, a, 100));
    CHECK(!verify(0, b, 100));
    CHECK(verify(0, a, 2099));
    CHECK(!verify(0, a, 2100));
    REQUIRE(refresh(0, 1100, 2));  // HTTP failure does not renew the lease.
    CHECK(verify(0, a, 1100));
    CHECK(!verify(0, a, 2100));
    REQUIRE(refresh(0, 2100, 3));  // Malformed JSON does not renew it either.
    CHECK(!verify(0, a, 2100));
    REQUIRE(refresh(0, 3100, 4));
    CHECK(verify(0, a, 3100));
    REQUIRE(refresh(0, 4100, 5));  // Authoritative empty set removes keys immediately.
    CHECK(!verify(0, a, 4100));
    REQUIRE(refresh(0, 5100, 6));  // Same approved kid now owns a different RSA key.
    CHECK(!verify(0, a, 5100));
    CHECK(verify(0, b, 5100));
    CHECK(!verify(1, b, 5100));
    REQUIRE(refresh(1, 5100, 7));
    CHECK(verify(1, b, 5100));
    const u32 requests = __atomic_load_n(&origin.served, __ATOMIC_ACQUIRE);
    for (u32 i = 0; i < 10; ++i) CHECK(!verify(0, a, 5100));
    CHECK_EQ(__atomic_load_n(&origin.served, __ATOMIC_ACQUIRE), requests);
    policies.cancel(0);
    CHECK(verify(1, b, 5100));
    policies.maintain(0, 0);  // Failed clock invalidates its cache, not another shard.
    CHECK(!verify(0, b, 5100));
    CHECK(verify(1, b, 5100));
}

TEST(https_fetch, remote_key_import_checks_complete_set_and_never_expands_approved_ids) {
    test::Rs256Fixture fixture;
    REQUIRE(fixture.init());
    Rs256Policy policy;
    REQUIRE(policy.load(fixture.policy));
    const Str bad[] = {
        lit_str("null"),
        lit_str("{}"),
        lit_str(R"({"keys":{}})"),
        lit_str(R"({"keys":[{}]})"),
        lit_str(R"({"keys":[{"kid":"current","kty":"EC"}]})"),
        lit_str(R"({"keys":[{"kid":"same"},{"kid":"s\u0061me"}]})"),
        lit_str(R"({"keys":[{"kid":"current","kid":"other"}]})"),
    };
    for (Str value : bad) {
        Rs256KeySet keys;
        CHECK_EQ(policy.prepare_refresh(value, keys), Rs256Policy::Refresh::Invalid);
        CHECK(!keys.valid());
    }
    Rs256KeySet keys;
    CHECK_EQ(policy.prepare_refresh(lit_str(R"({"keys":[]})"), keys), Rs256Policy::Refresh::Empty);
    CHECK_EQ(policy.prepare_refresh(lit_str(R"({"keys":[{"kid":"unapproved","kty":"EC"}]})"), keys),
             Rs256Policy::Refresh::Empty);
    json::Document document;
    REQUIRE_EQ(policy.prepare_refresh(fixture_jwks(fixture, document), keys),
               Rs256Policy::Refresh::Ready);
    CHECK_EQ(keys.size(), 1u);
    CHECK(keys.kid_at(0).eq(lit_str("current")));
    CHECK(keys.kid_at(1).ptr == nullptr);
}

TEST(https_fetch, remote_endpoint_configuration_rejects_unbounded_or_ambiguous_inputs) {
    test::Rs256Fixture fixture;
    REQUIRE(fixture.init());
    const char* options[] = {
        R"({})",
        R"({"address":"127.0.0.1","port":443,"serverName":"localhost","ca":"ca.pem","path":"/keys","refreshSeconds":1,"maxAgeSeconds":2,"timeoutSeconds":5})",
        R"({"address":"127.0.0.1","port":0,"serverName":"localhost","ca":"ca.pem","path":"/keys","refreshSeconds":1,"maxAgeSeconds":2,"timeoutSeconds":5})",
        R"({"address":"localhost","port":443,"serverName":"localhost","ca":"ca.pem","path":"/keys","refreshSeconds":1,"maxAgeSeconds":2,"timeoutSeconds":5})",
        R"({"address":"127.0.0.1","port":443,"serverName":"localhost","ca":"ca.pem","path":"/keys\r\nX: injected","refreshSeconds":1,"maxAgeSeconds":2,"timeoutSeconds":5})",
        R"({"address":"127.0.0.1","port":443,"serverName":"localhost","ca":"ca.pem","path":"/keys\u0000tail","refreshSeconds":1,"maxAgeSeconds":2,"timeoutSeconds":5})",
        R"({"address":"127.0.0.1","port":443,"serverName":"localhost","ca":"ca.pem","path":"/keys","refreshSeconds":2,"maxAgeSeconds":2,"timeoutSeconds":5})",
        R"({"address":"127.0.0.1","port":443,"serverName":"localhost","ca":"ca.pem","path":"/keys","refreshSeconds":1,"maxAgeSeconds":2,"timeoutSeconds":61})",
        R"({"address":"127.0.0.1","port":443,"serverName":"localhost","ca":"ca.pem","path":"/keys","refreshSeconds":1,"maxAgeSeconds":2,"timeoutSeconds":5,"url":"http://evil"})",
        R"({"address":"127.0.0.1","port":443,"serverName":"localhost","ca":"ca.pem","path":"/keys","refreshSeconds":1,"refreshSeconds":2,"maxAgeSeconds":3,"timeoutSeconds":5})",
    };
    for (u32 i = 0; i < sizeof(options) / sizeof(options[0]); ++i) {
        char bytes[8192];
        const int length = snprintf(bytes,
                                    sizeof(bytes),
                                    "%.*s,\"remoteJwks\":%s}",
                                    fixture.policy.len - 1,
                                    fixture.policy.ptr,
                                    options[i]);
        REQUIRE(length > 0 && static_cast<u32>(length) < sizeof(bytes));
        Rs256Policy policy;
        CHECK_EQ(policy.load({bytes, static_cast<u32>(length)}), i == 1);
    }
}

TEST(https_fetch, failed_tls_activation_cannot_serve_bootstrap_or_initialize_on_verification) {
    test::Rs256Fixture fixture;
    REQUIRE(fixture.init());
    char bytes[8192];
    const int size = snprintf(
        bytes,
        sizeof(bytes),
        "%.*s,\"remoteJwks\":{\"address\":\"127.0.0.1\",\"port\":443,\"serverName\":\"localhost\","
        "\"ca\":\"/missing/rut-test-ca.pem\",\"path\":\"/"
        "keys\",\"refreshSeconds\":1,\"maxAgeSeconds\":2,\"timeoutSeconds\":5}}",
        fixture.policy.len - 1,
        fixture.policy.ptr);
    REQUIRE(size > 0 && static_cast<u32>(size) < sizeof(bytes));
    const Str policy{bytes, static_cast<u32>(size)};
    Rs256Policies policies;
    REQUIRE(policies.load(&policy, 1));
    CHECK(!policies.activate(0));
    CHECK(!policies.activate(0));
    char token_bytes[4096], payload[8192];
    const Str token =
        fixture.sign(test::Rs256Fixture::header, test::Rs256Fixture::claims, token_bytes);
    json::Document document;
    u32 length = 99;
    CHECK(!policies.verify(0, policy, document, token, 100, payload, sizeof(payload), length, 100));
    CHECK_EQ(length, 0u);
    CHECK(!document.valid);
    policies.maintain(0, 100);
    policies.cancel(0);
    CHECK(!policies.verify(0, policy, document, token, 100, payload, sizeof(payload), length, 100));
}

TEST(https_fetch, only_authenticated_tls_eof_completes_a_close_delimited_body) {
    const bool clean[] = {true, false};
    for (bool close_notify : clean) {
        TlsOrigin origin;
        origin.responses[0] = lit_str(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: "
            "close\r\n\r\n{\"keys\":[]}");
        origin.count = 1;
        origin.clean_close = close_notify;
        REQUIRE(origin.init());
        HttpsFetch fetch;
        REQUIRE(fetch.init(origin.endpoint()));
        REQUIRE(fetch.start(jwt_monotonic_ms(), 3000));
        for (u32 i = 0; i < 3000 && fetch.state() == HttpsFetch::State::Busy; ++i) {
            fetch.advance(jwt_monotonic_ms());
            usleep(1000);
        }
        CHECK_EQ(fetch.state(), close_notify ? HttpsFetch::State::Done : HttpsFetch::State::Failed);
        if (close_notify)
            CHECK(fetch.body().eq(lit_str("{\"keys\":[]}")));
        else
            CHECK(fetch.body().ptr == nullptr);
    }
}
