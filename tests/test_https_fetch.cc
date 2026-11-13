#include "es256_fixture.h"
#include "posix.h"
#include "rs256_fixture.h"
#include "rut/runtime/es256_policy.h"
#include "rut/runtime/forward_auth.h"
#include "rut/runtime/http_call.h"
#include "rut/runtime/https_fetch.h"
#include "rut/runtime/net_client.h"
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
                    const int n = SSL_read(ssl,
                                           self.request + length,
                                           static_cast<int>(sizeof(self.request) - 1 - length));
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
                    const int n = SSL_write(ssl, response.ptr + offset, static_cast<int>(size));
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

template <typename Fixture>
static int print_remote_fixture(bool discovery = false) {
    Fixture first, second;
    if (!first.init() || !second.init()) return 2;
    const Str claims =
        discovery
            ? lit_str(
                  R"({"sub":"alice","iss":"https://localhost","aud":"gateway","exp":4102444800})")
            : Fixture::claims;
    if (discovery) {
        Fixture* fixtures[] = {&first, &second};
        for (Fixture* fixture : fixtures) {
            json::Document document;
            if (!document.parse(fixture->policy)) return 2;
            const u32 node = document.pointer(lit_str("/jwks"));
            if (node == json::kNone) return 2;
            char keys[4096];
            const Str raw = document.raw(node);
            if (raw.len >= sizeof(keys)) return 2;
            memcpy(keys, raw.ptr, raw.len);
            const int size = snprintf(
                fixture->policy_bytes,
                sizeof(fixture->policy_bytes),
                "{\"issuer\":\"https://"
                "localhost\",\"audience\":\"gateway\",\"kids\":[\"current\"],\"jwks\":%.*s}",
                raw.len,
                keys);
            if (size <= 0 || static_cast<u32>(size) >= sizeof(fixture->policy_bytes)) return 2;
            fixture->policy = {fixture->policy_bytes, static_cast<u32>(size)};
        }
    }
    char a_bytes[4096], b_bytes[4096];
    const Str a = first.sign(Fixture::header, claims, a_bytes);
    const Str b = second.sign(Fixture::header, claims, b_bytes);
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

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    if (argc == 2 && strcmp(argv[1], "--fixture") == 0)
        return print_remote_fixture<test::Rs256Fixture>();
    if (argc == 2 && strcmp(argv[1], "--fixture-es256") == 0)
        return print_remote_fixture<test::Es256Fixture>();
    if (argc == 2 && strcmp(argv[1], "--fixture-discovery") == 0)
        return print_remote_fixture<test::Rs256Fixture>(true);
    if (argc == 2 && strcmp(argv[1], "--fixture-es256-discovery") == 0)
        return print_remote_fixture<test::Es256Fixture>(true);
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

template <typename Fixture>
static Str fixture_jwks(Fixture& fixture, json::Document& document) {
    if (!document.parse(fixture.policy)) return {};
    for (u32 n = document.nodes[0].child; n != json::kNone; n = document.nodes[n].next) {
        json::Writer name{document.scratch};
        if (!document.string(document.nodes[n].key, name)) return {};
        if (Str{document.scratch, name.len}.eq(lit_str("jwks"))) return document.raw(n);
    }
    return {};
}

template <typename Fixture, typename Policies>
static void remote_rotation(test::TestCase* _tc) {
    Fixture first, second;
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
    Policies policies;
    REQUIRE(policies.load(&policy, 1));
    REQUIRE(policies.activate(0));
    REQUIRE(policies.activate(1));
    char a_bytes[4096], b_bytes[4096], payload[8192];
    const Str a = first.sign(Fixture::header, Fixture::claims, a_bytes);
    const Str b = second.sign(Fixture::header, Fixture::claims, b_bytes);
    REQUIRE(a.len && b.len);
    u32 length = 7;
    const auto verify = [&](u32 shard, Str token, u64 now) {
        const bool valid = policies.verify(
            shard, policy, document, token, 100, payload, sizeof(payload), length, now);
        if (!valid) {
            CHECK_EQ(length, 0u);
            CHECK(!document.valid);
            CHECK_EQ(document.count, 0u);
            CHECK(document.source.ptr == nullptr);
        }
        return valid;
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
    REQUIRE(refresh(0, 5100, 6));  // Same approved kid now owns a different signing key.
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

TEST(https_fetch, remote_jwks_rotation_failure_expiry_empty_set_and_shard_isolation) {
    remote_rotation<test::Rs256Fixture, Rs256Policies>(_tc);
}

TEST(https_fetch, es256_remote_jwks_rotation_failure_expiry_empty_set_and_shard_isolation) {
    remote_rotation<test::Es256Fixture, Es256Policies>(_tc);
}

template <typename Fixture, typename Policy, typename Keys>
static void remote_key_import(test::TestCase* _tc) {
    Fixture fixture;
    REQUIRE(fixture.init());
    Policy policy;
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
        Keys keys;
        CHECK_EQ(policy.prepare_refresh(value, keys), Policy::Refresh::Invalid);
        CHECK(!keys.valid());
    }
    Keys keys;
    CHECK_EQ(policy.prepare_refresh(lit_str(R"({"keys":[]})"), keys), Policy::Refresh::Empty);
    CHECK_EQ(policy.prepare_refresh(lit_str(R"({"keys":[{"kid":"unapproved","kty":"EC"}]})"), keys),
             Policy::Refresh::Empty);
    json::Document document;
    REQUIRE_EQ(policy.prepare_refresh(fixture_jwks(fixture, document), keys),
               Policy::Refresh::Ready);
    CHECK_EQ(keys.size(), 1u);
    CHECK(keys.kid_at(0).eq(lit_str("current")));
    CHECK(keys.kid_at(1).ptr == nullptr);
}

TEST(https_fetch, remote_key_import_checks_complete_set_and_never_expands_approved_ids) {
    remote_key_import<test::Rs256Fixture, Rs256Policy, Rs256KeySet>(_tc);
}

TEST(https_fetch, es256_remote_key_import_checks_complete_set_and_never_expands_approved_ids) {
    remote_key_import<test::Es256Fixture, Es256Policy, Es256KeySet>(_tc);
}

TEST(https_fetch, es256_refresh_rejects_invalid_selected_key_material) {
    test::Es256Fixture fixture;
    REQUIRE(fixture.init());
    Es256Policy policy;
    REQUIRE(policy.load(fixture.policy));
    json::Document document;
    const Str jwks = fixture_jwks(fixture, document);
    REQUIRE(jwks.len);
    const char* fields[] = {R"("alg":"ES384")",
                            R"("crv":"P-384")",
                            R"("d":"AA")",
                            R"("x":"AA")",
                            R"("key_ops":["sign"])"};
    // Duplicate members are rejected too, even if the original valid member
    // would otherwise make the selected key appear usable.
    for (const char* field : fields) {
        char bytes[4096];
        const int size =
            snprintf(bytes, sizeof(bytes), "%.*s,%s}]}", jwks.len - 3, jwks.ptr, field);
        REQUIRE(size > 0 && static_cast<u32>(size) < sizeof(bytes));
        Es256KeySet keys;
        CHECK_EQ(policy.prepare_refresh({bytes, static_cast<u32>(size)}, keys),
                 Es256Policy::Refresh::Invalid);
        CHECK(!keys.valid());
    }
}

TEST(https_fetch, es256_separate_import_clears_failed_policy_extensions) {
    test::Es256Fixture fixture;
    REQUIRE(fixture.init());
    Es256Policy policy;
    CHECK(!policy.load(lit_str(
        R"({"issuer":"issuer","audience":"gateway","revokedJtis":[],"issuedAfter":50,"remoteJwks":{"address":"127.0.0.1","port":443,"serverName":"localhost","ca":"ca.pem","path":"/keys","refreshSeconds":1,"maxAgeSeconds":2,"timeoutSeconds":1},"kids":["current"],"jwks":{"keys":[]}})")));
    CHECK(policy.remote().enabled());
    json::Document document;
    const Str approved[] = {lit_str("current")};
    REQUIRE(policy.load_jwks(
        fixture_jwks(fixture, document), lit_str("issuer"), lit_str("gateway"), approved, 1));
    CHECK(!policy.remote().enabled());
    REQUIRE(document.parse(test::Es256Fixture::claims));
    CHECK(policy.permits(document));
}

template <typename Fixture, typename Policy>
static void remote_configuration(test::TestCase* _tc) {
    Fixture fixture;
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
        Policy policy;
        CHECK_EQ(policy.load({bytes, static_cast<u32>(length)}), i == 1);
    }
}

TEST(https_fetch, remote_endpoint_configuration_rejects_unbounded_or_ambiguous_inputs) {
    remote_configuration<test::Rs256Fixture, Rs256Policy>(_tc);
}

TEST(https_fetch, es256_remote_endpoint_configuration_rejects_unbounded_or_ambiguous_inputs) {
    remote_configuration<test::Es256Fixture, Es256Policy>(_tc);
}

template <typename Fixture, typename Policies>
static void failed_remote_activation(test::TestCase* _tc) {
    Fixture fixture;
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
    Policies policies;
    REQUIRE(policies.load(&policy, 1));
    CHECK(!policies.activate(0));
    CHECK(!policies.activate(0));
    char token_bytes[4096], payload[8192];
    const Str token = fixture.sign(Fixture::header, Fixture::claims, token_bytes);
    json::Document document;
    u32 length = 99;
    CHECK(!policies.verify(0, policy, document, token, 100, payload, sizeof(payload), length, 100));
    CHECK_EQ(length, 0u);
    CHECK(!document.valid);
    policies.maintain(0, 100);
    policies.cancel(0);
    CHECK(!policies.verify(0, policy, document, token, 100, payload, sizeof(payload), length, 100));
}

TEST(https_fetch, failed_tls_activation_cannot_serve_bootstrap_or_initialize_on_verification) {
    failed_remote_activation<test::Rs256Fixture, Rs256Policies>(_tc);
}

TEST(https_fetch,
     es256_failed_tls_activation_cannot_serve_bootstrap_or_initialize_on_verification) {
    failed_remote_activation<test::Es256Fixture, Es256Policies>(_tc);
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

TEST(https_fetch, authorization_profile_is_bounded_and_does_not_relax_jwks) {
    const char* valid[] = {
        "HTTP/1.1 200 OK\r\nX-Consumer-ID: alice\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 403 Forbidden\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
    };
    for (const auto* response : valid) {
        BoundedJsonResponse auth, jwks;
        auth.reset(true);
        jwks.reset();
        CHECK_EQ(auth.append(text(response)), BoundedJsonResponse::Result::Complete);
        CHECK_EQ(jwks.append(text(response)), BoundedJsonResponse::Result::Error);
    }
    const char* invalid[] = {
        "HTTP/1.1 302 Found\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 8193\r\n\r\n",
        "HTTP/1.1 200 OK\r\nConnection: X-Consumer-ID\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n",
    };
    for (const auto* response : invalid) {
        BoundedJsonResponse auth;
        auth.reset(true);
        CHECK_EQ(auth.append(text(response)), BoundedJsonResponse::Result::Error);
    }
    BoundedJsonResponse duplicate;
    duplicate.reset(true);
    REQUIRE_EQ(duplicate.append(lit_str("HTTP/1.1 200 OK\r\nX-Consumer-ID: a\r\nx-consumer-id: "
                                        "b\r\nContent-Length: 0\r\n\r\n")),
               BoundedJsonResponse::Result::Complete);
    CHECK_EQ(duplicate.unique_header(lit_str("X-Consumer-ID")).len, 0u);
}

TEST(https_fetch, forward_auth_policy_rejects_unsafe_identity_and_endpoint) {
    char bytes[2048];
    const char* identities[] = {"X-Consumer-ID",
                                "Authorization",
                                "Host",
                                "Connection",
                                "X-Original-URI",
                                "X-Original-Method",
                                "X-Bad Header",
                                "X-"};
    for (const char* identity : identities) {
        const int length =
            snprintf(bytes,
                     sizeof(bytes),
                     "{\"address\":\"127.0.0.1\",\"serverName\":\"localhost\",\"caFile\":\"/"
                     "ca.pem\",\"path\":\"/auth\",\"identityHeader\":\"%s\"}",
                     identity);
        CHECK_EQ(forward_auth_policy_valid(
                     lit_str("Authorization"), {bytes, static_cast<u32>(length)}, 5000),
                 __builtin_strcmp(identity, "X-Consumer-ID") == 0);
    }
    const Str policy = lit_str(
        R"json({"address":"127.0.0.1","serverName":"localhost","caFile":"/ca.pem","path":"/auth","identityHeader":"X-Consumer-ID"})json");
    CHECK(forward_auth_policy_valid(lit_str("Authorization"), policy, 5000));
    CHECK(!forward_auth_policy_valid(lit_str("Authorization"), policy, 0));
    CHECK(!forward_auth_policy_valid(lit_str("Authorization"), policy, 60001));
    CHECK(!forward_auth_policy_valid(lit_str("x-consumer-id"), policy, 5000));
    ForwardAuthPolicy config;
    CHECK(!config.load(lit_str(
        R"json({"address":"127.0.0.1","address":"127.0.0.2","serverName":"localhost","caFile":"/ca.pem","path":"/auth","identityHeader":"X-Consumer-ID"})json")));
    CHECK(!config.load(lit_str(
        R"json({"address":"127.0.0.1","serverName":"localhost","caFile":"/ca.pem","path":"/auth\u0000ignored","identityHeader":"X-Consumer-ID"})json")));
}

TEST(https_fetch, forward_auth_worker_bounds_deadline_cancellation_and_generation) {
    TlsOrigin origin;
    origin.responses[0] =
        lit_str("HTTP/1.1 200 OK\r\nX-Consumer-ID: alice\r\nContent-Length: 0\r\n\r\n");
    origin.count = 1;
    REQUIRE(origin.init());
    ForwardAuthPolicy policy;
    policy.endpoint = origin.endpoint();
    __builtin_memcpy(policy.identity_header, "X-Consumer-ID", 14);
    ForwardAuthWorker worker;
    REQUIRE(worker.start().has_value());
    const auto now = jwt_monotonic_ms();
    for (u32 i = 0; i < ForwardAuthWorker::kCapacity; ++i) {
        auto reply = worker.authorize(i + 1,
                                      1,
                                      lit_str("Authorization"),
                                      policy,
                                      lit_str("Bearer secret"),
                                      lit_str("GET"),
                                      lit_str("/resource"),
                                      now,
                                      3000);
        CHECK_EQ(reply.status, static_cast<i32>(0x80000000u));
    }
    CHECK_EQ(worker
                 .authorize(100,
                            1,
                            lit_str("Authorization"),
                            policy,
                            lit_str("x"),
                            lit_str("GET"),
                            lit_str("/"),
                            now,
                            3000)
                 .status,
             -1);
    // Expiry wins over a queued/running/completed authorization decision.
    CHECK_EQ(worker.authorize(1, 1, {}, policy, {}, {}, {}, now + 3000, 60000).status, -2);
    for (u32 i = 2; i <= ForwardAuthWorker::kCapacity; ++i) worker.cancel(i);
    ForwardAuthReply reply;
    for (u32 i = 0; i < 3000; ++i) {
        reply = worker.authorize(1,
                                 2,
                                 lit_str("Authorization"),
                                 policy,
                                 lit_str("Bearer fresh"),
                                 lit_str("GET"),
                                 lit_str("/new"),
                                 jwt_monotonic_ms(),
                                 3000);
        if (reply.status == 1) break;
        CHECK(reply.status == -1 || reply.status == static_cast<i32>(0x80000000u));
        usleep(1000);
    }
    CHECK_EQ(reply.status, 1);
    CHECK((Str{reply.identity, reply.identity_length}.eq(lit_str("alice"))));
    worker.stop();
    CHECK_EQ(worker.authorize(1, 3, {}, policy, {}, {}, {}, jwt_monotonic_ms(), 3000).status, -1);
    REQUIRE(worker.start().has_value());
    worker.cancel(1);
    worker.stop();
}

TEST(https_fetch, callout_request_rejects_transport_injection_and_preserves_body) {
    HttpsEndpoint endpoint;
    REQUIRE(http_call_policy(
        lit_str(
            R"({"address":"127.0.0.1","serverName":"localhost","caFile":"/ca.pem","path":"/check?x=1"})"),
        endpoint));
    char wire[6144];
    u32 length = 0;
    REQUIRE(http_call_request(
        endpoint,
        lit_str(
            R"({"method":"POST","headers":{"Authorization":"Bearer secret","Content-Type":"application/json"},"body":"{\"user\":\"alice\"}"})"),
        wire,
        sizeof(wire),
        length));
    wire[length] = 0;
    CHECK(strstr(wire, "POST /check?x=1 HTTP/1.1\r\n") != nullptr);
    CHECK(strstr(wire, "Content-Length: 16\r\n") != nullptr);
    CHECK(strstr(wire, "\r\n\r\n{\"user\":\"alice\"}") != nullptr);
    const Str bad[] = {lit_str(R"({"method":"CONNECT"})"),
                       lit_str(R"({"method":"GET","url":"http://attacker"})"),
                       lit_str(R"({"method":"GET","headers":{"Host":"attacker"}})"),
                       lit_str(R"({"method":"GET","headers":{"Content-Length":"99"}})"),
                       lit_str(R"({"method":"GET","headers":{"X-A":"one","x-a":"two"}})"),
                       lit_str(R"({"method":"GET","headers":{"X-A":"one\r\nInjected: yes"}})"),
                       lit_str(R"({"method":"GET","method":"POST"})")};
    for (auto input : bad) CHECK(!http_call_request(endpoint, input, wire, sizeof(wire), length));
    CHECK(!http_call_policy(
        lit_str(
            R"({"address":"example.com","serverName":"localhost","caFile":"/ca.pem","path":"/"})"),
        endpoint));
}

TEST(https_fetch, callout_profile_admits_http_errors_but_not_ambiguous_or_partial_messages) {
    BoundedJsonResponse response;
    response.reset_callout();
    CHECK(response.append(lit_str(
              "HTTP/1.1 403 Forbidden\r\nContent-Length: 3\r\nX-A: one\r\nX-A: two\r\n\r\nno!")) ==
          BoundedJsonResponse::Result::Complete);
    CHECK_EQ(response.status(), 403u);
    CHECK(response.body().eq(lit_str("no!")));
    ParsedResponse headers{};
    REQUIRE(response.headers(headers));
    CHECK_EQ(headers.header_count, 3u);
    response.reset_callout();
    CHECK(response.append(lit_str(
              "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n")) ==
          BoundedJsonResponse::Result::Complete);
    CHECK(response.body().eq(lit_str("ok")));
    const Str bad[] = {
        lit_str("HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx"),
        lit_str("HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\nx"),
        lit_str("HTTP/1.1 101 Switching Protocols\r\nContent-Length: 0\r\n\r\n"),
        lit_str("HTTP/1.1 204 No Content\r\nContent-Length: 1\r\n\r\nx")};
    for (auto message : bad) {
        response.reset_callout();
        CHECK(response.append(message) == BoundedJsonResponse::Result::Error);
    }
    response.reset_callout();
    CHECK(response.append(lit_str("HTTP/1.1 204 No Content\r\n\r\n")) ==
          BoundedJsonResponse::Result::Complete);
    response.reset_callout();
    CHECK(response.append(lit_str("HTTP/1.1 304 Not Modified\r\nContent-Length: 100000\r\n\r\n")) ==
          BoundedJsonResponse::Result::Complete);
    CHECK(response.body().empty());
    response.reset_callout();
    CHECK(
        response.append(lit_str("HTTP/1.1 304 Not Modified\r\nContent-Length: 100000\r\n\r\nx")) ==
        BoundedJsonResponse::Result::Error);
    response.reset_callout();
    CHECK(response.append(lit_str("HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n")) ==
          BoundedJsonResponse::Result::Error);
    response.reset_callout();
    CHECK(response.append(lit_str("HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nx")) ==
          BoundedJsonResponse::Result::More);
    CHECK(response.finish() == BoundedJsonResponse::Result::Error);
    // Existing authorization and JWKS profiles retain their narrower domains.
    response.reset(true);
    CHECK(response.append(lit_str("HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\n\r\n")) ==
          BoundedJsonResponse::Result::Error);
}

TEST(https_fetch, callout_worker_deadline_capacity_cancellation_and_owned_results) {
    TlsOrigin origin;
    origin.responses[0] = lit_str(
        "HTTP/1.1 403 Forbidden\r\nX-User: alice\r\nX-Role: reader\r\nX-Role: "
        "writer\r\nContent-Length: 2\r\n\r\n{}");
    origin.count = 1;
    REQUIRE(origin.init());
    HttpCallWorker worker;
    REQUIRE(worker.start().has_value());
    const auto endpoint = origin.endpoint();
    const auto request = lit_str(R"({"method":"GET"})");
    const auto now = jwt_monotonic_ms();
    for (u32 i = 1; i <= HttpCallWorker::kCapacity; ++i)
        CHECK_EQ(worker.call(i, 1, endpoint, request, now, 3000).status,
                 static_cast<i32>(0x80000000u));
    CHECK_EQ(worker.call(100, 1, endpoint, request, now, 3000).status, -3);
    CHECK_EQ(worker.call(1, 1, endpoint, {}, now + 3000, 60000).status, -2);
    for (u32 i = 2; i <= HttpCallWorker::kCapacity; ++i) worker.cancel(i);
    HttpCallReply reply;
    for (u32 i = 0; i < 3000; ++i) {
        reply = worker.call(1, 2, endpoint, request, jwt_monotonic_ms(), 3000);
        if (reply.status == 0) break;
        CHECK(reply.status == -3 || reply.status == static_cast<i32>(0x80000000u));
        usleep(1000);
    }
    CHECK_EQ(reply.status, 0);
    reply.document[reply.length] = 0;
    CHECK(strstr(reply.document, "\"status\":403") != nullptr);
    CHECK(strstr(reply.document, "\"x-role\":[\"reader\",\"writer\"]") != nullptr);
    worker.stop();
    CHECK_EQ(worker.call(1, 3, endpoint, request, jwt_monotonic_ms(), 3000).status, -1);
    REQUIRE(worker.start().has_value());
    worker.stop();
}

TEST(net_client, fixed_endpoint_policy_rejects_unknown_duplicate_and_unsafe_tls_fields) {
    NetEndpoint endpoint;
    CHECK(net_endpoint(lit_str(R"({"address":"127.0.0.1","port":6379})"), false, endpoint));
    CHECK(!endpoint.tls.enabled);
    CHECK(net_endpoint(
        lit_str(
            R"({"address":"127.0.0.1","port":6379,"tls":true,"caFile":"/ca.pem","serverName":"localhost"})"),
        false,
        endpoint));
    CHECK(endpoint.tls.enabled);
    const char* invalid[] = {
        "{}",
        R"({"address":"bad..host","port":1})",
        R"({"address":"127.0.0.1","port":0})",
        R"({"address":"127.0.0.1","port":65536})",
        R"({"address":"127.0.0.1","port":1,"p\u006frt":2})",
        R"({"address":"127.0.0.1","port":1,"tls":true})",
        R"({"address":"127.0.0.1","port":1,"caFile":"/ca.pem"})",
        R"({"address":"127.0.0.1","port":1,"path":"/"})",
        R"({"address":"127.0.0.1","port":1,"tls":"false"})",
        R"({"address":"127.0.0.1\u0000","port":1})",
    };
    for (const char* input : invalid) CHECK(!net_endpoint(text(input), false, endpoint));
    CHECK(
        !net_endpoint(lit_str(R"({"address":"127.0.0.1","port":1,"tls":false})"), true, endpoint));
}

TEST(net_client, bounded_sessions_validate_owner_generation_close_and_cancel) {
    NetClientWorker worker;
    REQUIRE(worker.start().has_value());
    NetEndpoint endpoint;
    REQUIRE(net_endpoint(lit_str(R"({"address":"127.0.0.1","port":6379})"), true, endpoint));
    u32 handles[NetClientWorker::kCapacity]{};
    for (u32 i = 0; i < NetClientWorker::kCapacity; ++i) {
        NetReply reply;
        for (u32 attempt = 0; attempt < 1000; ++attempt) {
            reply =
                worker.call(i + 1, 1, NetOp::Udp, 0, &endpoint, {}, 0, jwt_monotonic_ms(), 3000);
            if (reply.status != NetReply::kPending) break;
            usleep(1000);
        }
        REQUIRE(reply.status == 0);
        REQUIRE(reply.scalar != 0);
        handles[i] = reply.scalar;
    }
    CHECK_EQ(worker.call(100, 1, NetOp::Udp, 0, &endpoint, {}, 0, jwt_monotonic_ms(), 3000).status,
             -3);
    CHECK_EQ(
        worker.call(100, 1, NetOp::Close, handles[0], nullptr, {}, 0, jwt_monotonic_ms(), 1).status,
        -4);
    CHECK_EQ(
        worker.call(1, 2, NetOp::Close, handles[0], nullptr, {}, 0, jwt_monotonic_ms(), 1).status,
        -4);
    const auto closed =
        worker.call(1, 1, NetOp::Close, handles[0], nullptr, {}, 0, jwt_monotonic_ms(), 1);
    CHECK_EQ(closed.status, 0);
    CHECK_EQ(closed.scalar, 1u);
    CHECK_EQ(
        worker
            .call(1, 1, NetOp::Send, handles[0], nullptr, lit_str("x"), 0, jwt_monotonic_ms(), 100)
            .status,
        -4);
    for (u32 i = 1; i < NetClientWorker::kCapacity; ++i) worker.cancel(i + 1, 1);
    NetReply reply;
    for (u32 attempt = 0; attempt < 1000; ++attempt) {
        reply = worker.call(1, 2, NetOp::Udp, 0, &endpoint, {}, 0, jwt_monotonic_ms(), 3000);
        if (reply.status == 0) break;
        CHECK(reply.status == -3 || reply.status == NetReply::kPending);
        usleep(1000);
    }
    CHECK_EQ(reply.status, 0);
    CHECK(reply.scalar != handles[0]);
    CHECK_EQ(
        worker.call(1, 2, NetOp::Receive, reply.scalar, nullptr, {}, 8193, jwt_monotonic_ms(), 100)
            .status,
        -4);
    worker.stop();
    REQUIRE(worker.start().has_value());
    worker.stop();
}

namespace {
struct PoolOrigin {
    int listener = -1;
    int peers[64]{};
    u32 count = 0;
    u16 port = 0;
    PoolOrigin() {
        for (auto& peer : peers) peer = -1;
    }
    ~PoolOrigin() {
        for (auto peer : peers)
            if (peer >= 0) ::close(peer);
        if (listener >= 0) ::close(listener);
    }
    bool init() {
        listener = rut::test::cloexec_socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (listener < 0 ||
            bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) ||
            listen(listener, 32))
            return false;
        socklen_t size = sizeof(address);
        if (getsockname(listener, reinterpret_cast<sockaddr*>(&address), &size)) return false;
        port = ntohs(address.sin_port);
        return true;
    }
    int accept_one() {
        pollfd ready{listener, POLLIN, 0};
        if (count == 64 || poll(&ready, 1, 1000) != 1) return -1;
        const int fd = accept(listener, nullptr, nullptr);
        if (fd >= 0) peers[count++] = fd;
        return fd;
    }
    bool no_connect() {
        pollfd ready{listener, POLLIN, 0};
        return poll(&ready, 1, 0) == 0;
    }
};
NetReply pool_call(NetClientWorker& worker,
                   NetOp op,
                   u32 owner,
                   u64 generation,
                   u32 handle,
                   const NetEndpoint* endpoint = nullptr,
                   const void* config = nullptr,
                   i32 amount = 0) {
    NetReply reply;
    for (u32 i = 0; i < 2000; ++i) {
        reply = worker.call(
            owner, generation, op, handle, endpoint, {}, amount, jwt_monotonic_ms(), 1500, config);
        if (reply.status != NetReply::kPending) return reply;
        usleep(1000);
    }
    return reply;
}
}  // namespace

TEST(net_client, explicit_pool_leases_fence_aliases_and_retired_configuration) {
    PoolOrigin origin;
    REQUIRE(origin.init());
    NetClientWorker worker;
    REQUIRE(worker.start().has_value());
    NetEndpoint endpoint;
    REQUIRE(net_endpoint(
        lit_str(R"({"address":"127.0.0.1","port":1,"poolIdleMs":1000})"), false, endpoint));
    endpoint.port = origin.port;
    int config_a = 0, config_b = 0;
    worker.adopt_config(&config_a);
    auto first = pool_call(worker, NetOp::Tcp, 1, 1, 0, &endpoint, &config_a);
    REQUIRE(first.status == 0);
    REQUIRE(origin.accept_one() >= 0);
    auto released = pool_call(worker, NetOp::Release, 1, 1, first.scalar);
    CHECK_EQ(released.status, 0);
    CHECK_EQ(released.scalar, 1u);
    CHECK_EQ(pool_call(worker, NetOp::Send, 1, 1, first.scalar).status, -4);
    worker.cancel(1, 1);  // completion must not kill a detached pooled transport
    auto second = pool_call(worker, NetOp::Tcp, 2, 7, 0, &endpoint, &config_a);
    REQUIRE(second.status == 0);
    CHECK(second.scalar != first.scalar);
    CHECK(origin.no_connect());
    CHECK_EQ(pool_call(worker, NetOp::Close, 1, 1, second.scalar).status, -4);
    CHECK_EQ(pool_call(worker, NetOp::Close, 2, 8, second.scalar).status, -4);
    worker.adopt_config(&config_b);
    // An active request under the retired config can finish, but cannot park.
    CHECK_EQ(pool_call(worker, NetOp::Release, 2, 7, second.scalar).scalar, 0u);
    auto third = pool_call(worker, NetOp::Tcp, 3, 1, 0, &endpoint, &config_b);
    REQUIRE(third.status == 0);
    REQUIRE(origin.accept_one() >= 0);
    CHECK_EQ(pool_call(worker, NetOp::Release, 3, 1, third.scalar).scalar, 1u);
    worker.adopt_config(&config_a);
    auto fourth = pool_call(worker, NetOp::Tcp, 4, 1, 0, &endpoint, &config_a);
    REQUIRE(fourth.status == 0);
    REQUIRE(origin.accept_one() >= 0);
    worker.cancel(4, 1);  // cancellation never implicitly returns an active lease
    usleep(10000);
    auto fifth = pool_call(worker, NetOp::Tcp, 5, 1, 0, &endpoint, &config_a);
    REQUIRE(fifth.status == 0);
    REQUIRE(origin.accept_one() >= 0);
    worker.stop();
}

TEST(net_client, pool_discards_buffered_eof_expired_and_unconfigured_transports) {
    PoolOrigin origin;
    REQUIRE(origin.init());
    NetClientWorker worker;
    REQUIRE(worker.start().has_value());
    NetEndpoint endpoint;
    REQUIRE(net_endpoint(
        lit_str(R"({"address":"127.0.0.1","port":1,"poolIdleMs":20})"), false, endpoint));
    endpoint.port = origin.port;
    auto first = pool_call(worker, NetOp::Tcp, 1, 1, 0, &endpoint);
    REQUIRE(first.status == 0);
    const int peer = origin.accept_one();
    REQUIRE(peer >= 0);
    REQUIRE(send(peer, "OK\r\nJUNK", 8, MSG_NOSIGNAL) == 8);
    auto line = pool_call(worker, NetOp::ReadLine, 1, 1, first.scalar, nullptr, nullptr, 64);
    REQUIRE(line.status == 0);
    CHECK_EQ(line.length, 4u);
    CHECK_EQ(pool_call(worker, NetOp::Release, 1, 1, first.scalar).scalar, 0u);
    auto second = pool_call(worker, NetOp::Tcp, 2, 1, 0, &endpoint);
    REQUIRE(second.status == 0);
    REQUIRE(origin.accept_one() >= 0);
    CHECK_EQ(pool_call(worker, NetOp::Release, 2, 1, second.scalar).scalar, 1u);
    usleep(40000);
    auto third = pool_call(worker, NetOp::Tcp, 3, 1, 0, &endpoint);
    REQUIRE(third.status == 0);
    REQUIRE(origin.accept_one() >= 0);
    CHECK_EQ(pool_call(worker, NetOp::Release, 3, 1, third.scalar).scalar, 1u);
    ::close(origin.peers[2]);
    origin.peers[2] = -1;
    usleep(5000);
    auto fourth = pool_call(worker, NetOp::Tcp, 4, 1, 0, &endpoint);
    REQUIRE(fourth.status == 0);
    REQUIRE(origin.accept_one() >= 0);
    CHECK_EQ(pool_call(worker, NetOp::Release, 4, 1, fourth.scalar).scalar, 1u);
    endpoint.pool_idle_ms = 0;
    auto fifth = pool_call(worker, NetOp::Tcp, 5, 1, 0, &endpoint);
    REQUIRE(fifth.status == 0);
    REQUIRE(origin.accept_one() >= 0);
    CHECK_EQ(pool_call(worker, NetOp::Release, 5, 1, fifth.scalar).scalar, 0u);
    worker.stop();
}

TEST(net_client, pool_policy_is_tcp_only_strict_and_bounded) {
    NetEndpoint endpoint;
    const char* invalid[] = {R"({"address":"127.0.0.1","port":1,"poolIdleMs":0})",
                             R"({"address":"127.0.0.1","port":1,"poolIdleMs":60001})",
                             R"({"address":"127.0.0.1","port":1,"poolIdleMs":1.5})",
                             R"({"address":"127.0.0.1","port":1,"poolIdleMs":"1000"})",
                             R"({"address":"127.0.0.1","port":1,"poolIdleMs":1,"poolIdleMs":2})"};
    for (const char* input : invalid) CHECK(!net_endpoint(text(input), false, endpoint));
    CHECK(!net_endpoint(
        lit_str(R"({"address":"127.0.0.1","port":1,"poolIdleMs":1})"), true, endpoint));
    CHECK(net_endpoint(
        lit_str(R"({"address":"127.0.0.1","port":1,"poolIdleMs":60000})"), false, endpoint));
}

TEST(net_client, idle_pool_capacity_does_not_consume_live_lease_slots) {
    PoolOrigin origin;
    REQUIRE(origin.init());
    NetClientWorker worker;
    REQUIRE(worker.start().has_value());
    NetEndpoint endpoint;
    REQUIRE(net_endpoint(
        lit_str(R"({"address":"127.0.0.1","port":1,"poolIdleMs":5000})"), false, endpoint));
    endpoint.port = origin.port;
    u32 handles[NetClientWorker::kCapacity]{};
    for (u32 i = 0; i < NetClientWorker::kCapacity; ++i) {
        auto result = pool_call(worker, NetOp::Tcp, i + 1, 1, 0, &endpoint);
        REQUIRE(result.status == 0);
        handles[i] = result.scalar;
        REQUIRE(origin.accept_one() >= 0);
    }
    for (u32 i = 0; i < NetClientWorker::kCapacity; ++i)
        CHECK_EQ(pool_call(worker, NetOp::Release, i + 1, 1, handles[i]).scalar, 1u);
    // Change an endpoint-key component: all parked entries remain in their own
    // pool while all sixteen live slots can still be independently leased.
    endpoint.pool_idle_ms = 4000;
    for (u32 i = 0; i < NetClientWorker::kCapacity; ++i) {
        auto result = pool_call(worker, NetOp::Tcp, i + 1, 2, 0, &endpoint);
        REQUIRE(result.status == 0);
        handles[i] = result.scalar;
        REQUIRE(origin.accept_one() >= 0);
    }
    for (u32 i = 0; i < NetClientWorker::kCapacity; ++i)
        CHECK_EQ(pool_call(worker, NetOp::Release, i + 1, 2, handles[i]).scalar, 0u);
    worker.stop();
}

namespace {
struct DnsOrigin {
    int fd = -1;
    u16 port = 0;
    bool init() {
        fd = test::cloexec_socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0 || fcntl(fd, F_SETFL, O_NONBLOCK) < 0) return false;
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (fd < 0 || bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0)
            return false;
        socklen_t size = sizeof(address);
        if (getsockname(fd, reinterpret_cast<sockaddr*>(&address), &size) != 0) return false;
        port = ntohs(address.sin_port);
        return true;
    }
    bool reply(bool allowed) {
        u8 packet[512]{};
        sockaddr_in peer{};
        socklen_t size = sizeof(peer);
        const auto length =
            recvfrom(fd, packet, sizeof(packet) - 16, 0, reinterpret_cast<sockaddr*>(&peer), &size);
        if (length < 0) return false;
        packet[2] = 0x81;
        packet[3] = 0x80;
        packet[7] = 1;
        const u8 answer[] = {
            0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 127, 0, 0, static_cast<u8>(allowed ? 1 : 2)};
        __builtin_memcpy(packet + length, answer, sizeof(answer));
        return sendto(fd,
                      packet,
                      static_cast<u32>(length) + sizeof(answer),
                      0,
                      reinterpret_cast<sockaddr*>(&peer),
                      size) == length + static_cast<ssize_t>(sizeof(answer));
    }
    ~DnsOrigin() {
        if (fd >= 0) close(fd);
    }
};
void complete_jwks(JwksFetch& fetch, DnsOrigin* resolver = nullptr, bool allowed = true) {
    for (u32 i = 0; i < 3000 && fetch.state() == JwksFetch::State::Busy; ++i) {
        if (resolver) (void)resolver->reply(allowed);
        fetch.advance(jwt_monotonic_ms());
        usleep(1000);
    }
}
}  // namespace
TEST(https_fetch, jwks_dns_discovery_lifecycle_and_recovery) {
    signal(SIGPIPE, SIG_IGN);
    DnsOrigin dns;
    REQUIRE(dns.init());
    TlsOrigin origin;
    REQUIRE(origin.init());
    char discovery[2048];
    char body[1024];
    const int body_length =
        snprintf(body,
                 sizeof(body),
                 "{\"issuer\":\"https://localhost/tenant\",\"jwks_uri\":\"https://localhost:%u/"
                 "keys?profile=rs256\"}",
                 origin.port);
    const int size = snprintf(
        discovery,
        sizeof(discovery),
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
        body_length,
        body);
    REQUIRE(size > 0);
    const Str keys = lit_str(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
        "11\r\n\r\n{\"keys\":[]}");
    origin.responses[0] = {discovery, static_cast<u32>(size)};
    origin.responses[1] = keys;
    origin.count = 2;
    RemoteJwks configuration;
    configuration.endpoint = origin.endpoint();
    strcpy(configuration.discovery_path, "/.well-known/openid-configuration");
    strcpy(configuration.discovery_issuer, "https://localhost/tenant");
    strcpy(configuration.dns_address, "127.0.0.1");
    strcpy(configuration.allowed_addresses[0], "127.0.0.1");
    configuration.allowed_count = 1;
    configuration.dns_port = dns.port;
    JwksFetch fetch;
    REQUIRE(fetch.init(configuration));
    CHECK(!fetch.start(0, 1000));
    CHECK(!fetch.start(jwt_monotonic_ms(), 0));
    REQUIRE(fetch.start(jwt_monotonic_ms(), 3000));
    CHECK(!fetch.init(RemoteJwks{}));
    CHECK(!fetch.start(jwt_monotonic_ms(), 3000));
    CHECK(fetch.body().len == 0);
    complete_jwks(fetch, &dns);
    REQUIRE_EQ(fetch.state(), JwksFetch::State::Done);
    CHECK(fetch.body().eq(lit_str("{\"keys\":[]}")));
    fetch.advance(0);  // A completed result is stable until explicit restart/cancel.
    CHECK_EQ(fetch.state(), JwksFetch::State::Done);
    REQUIRE(fetch.start(jwt_monotonic_ms(), 3000));
    complete_jwks(fetch, &dns, false);
    CHECK_EQ(fetch.state(), JwksFetch::State::Failed);
    CHECK_EQ(fetch.body().len, 0u);
    const u64 now = jwt_monotonic_ms();
    REQUIRE(fetch.start(now, 100));
    fetch.advance(now + 100);
    CHECK_EQ(fetch.state(), JwksFetch::State::Failed);
    REQUIRE(fetch.start(now, 100));
    fetch.advance(now - 1);
    CHECK_EQ(fetch.state(), JwksFetch::State::Failed);
    REQUIRE(fetch.start(now, 100));
    fetch.cancel();
    CHECK_EQ(fetch.state(), JwksFetch::State::Cancelled);
    fetch.advance(now + 1);
    CHECK_EQ(fetch.state(), JwksFetch::State::Cancelled);
}
TEST(https_fetch, jwks_discovery_rejects_mismatched_origin_and_uninitialized_fetch) {
    signal(SIGPIPE, SIG_IGN);
    TlsOrigin origin;
    origin.responses[0] =
        lit_str("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}");
    origin.count = 1;
    REQUIRE(origin.init());
    RemoteJwks configuration;
    configuration.endpoint = origin.endpoint();
    strcpy(configuration.discovery_path, "/discovery");
    strcpy(configuration.discovery_issuer, "https://localhost");
    JwksFetch fetch;
    REQUIRE(fetch.init(configuration));
    REQUIRE(fetch.start(jwt_monotonic_ms(), 2000));
    complete_jwks(fetch);
    CHECK_EQ(fetch.state(), JwksFetch::State::Failed);
    CHECK_EQ(fetch.body().len, 0u);
    JwksFetch uninitialized;
    CHECK(!uninitialized.start(jwt_monotonic_ms(), 1000));
    CHECK_EQ(uninitialized.state(), JwksFetch::State::Idle);
    configuration.discovery_path[0] = 'x';  // keys init succeeds, discovery init rejects.
    JwksFetch partial;
    CHECK(!partial.init(configuration));
    CHECK(!partial.start(jwt_monotonic_ms(), 1000));
    CHECK_EQ(partial.state(), JwksFetch::State::Idle);
}
