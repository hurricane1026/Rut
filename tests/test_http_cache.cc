#include "rut/runtime/http_cache.h"
#include "test.h"
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>

using namespace rut;
namespace {
constexpr u64 kWall = 1792972800ull * 1000000;  // Mon, 26 Oct 2026 00:00:00 GMT
HttpCache::Key key(const char* headers = "",
                   u64 config = 1,
                   const char* path = "/asset",
                   u32 route = 0) {
    std::string request =
        std::string("GET ") + path + " HTTP/1.1\r\nHost: example.com\r\n" + headers + "\r\n";
    HttpCache::Key result;
    HttpCache::make_key(reinterpret_cast<const u8*>(request.data()),
                        request.size(),
                        config,
                        route,
                        false,
                        0,
                        result);
    return result;
}
std::string response(const char* headers = "Cache-Control: max-age=60\r\n",
                     const char* body = "hello") {
    return std::string(
               "HTTP/1.1 200 OK\r\nDate: Mon, 26 Oct 2026 00:00:00 GMT\r\nContent-Length: ") +
           std::to_string(std::strlen(body)) + "\r\n" + headers + "\r\n" + body;
}
bool store(HttpCache& cache,
           const HttpCache::Key& request,
           const std::string& wire,
           u32 ttl = 60,
           u64 time = 1000000) {
    u8 output[HttpCache::kMaxResponse];
    u32 written = 0;
    HttpCache::Token token;
    if (cache.begin(request, ttl, time, true, output, sizeof(output), written, token) !=
        HttpCache::Result::Miss)
        return false;
    return cache.commit(token, reinterpret_cast<const u8*>(wire.data()), wire.size(), time, kWall);
}
HttpCache::Result lookup(HttpCache& cache,
                         const HttpCache::Key& request,
                         u64 now,
                         std::string* wire = nullptr) {
    u8 output[HttpCache::kMaxResponse];
    u32 written = 0;
    HttpCache::Token token;
    auto result = cache.begin(request, 60, now, true, output, sizeof(output), written, token);
    if (wire) wire->assign(reinterpret_cast<const char*>(output), written);
    cache.cancel(token);
    return result;
}
}  // namespace

TEST(http_cache, hit_age_expiry_and_owned_copy) {
    auto cache = std::make_unique<HttpCache>();
    auto request = key();
    REQUIRE(request.eligible);
    REQUIRE(store(*cache, request, response()));
    std::string wire;
    CHECK(lookup(*cache, request, 4000000, &wire) == HttpCache::Result::Hit);
    CHECK(wire.find("Age: 3\r\n") != std::string::npos);
    CHECK(wire.ends_with("hello"));
    cache->invalidate_host(request.config, request.host);
    CHECK(wire.ends_with("hello"));  // no cache view retained by downstream I/O
    CHECK(lookup(*cache, request, 4000000) == HttpCache::Result::Miss);
    REQUIRE(store(*cache, request, response()));
    CHECK(lookup(*cache, request, 60999999) == HttpCache::Result::Hit);
    CHECK(lookup(*cache, request, 61000000) == HttpCache::Result::Miss);
    CHECK(lookup(*cache, request, 999999) == HttpCache::Result::Miss);
}
TEST(http_cache, credentials_ranges_conditionals_and_controls_bypass) {
    const char* denied[] = {"Authorization: Bearer secret\r\n",
                            "X-API-Key: secret\r\n",
                            "authorization:\r\n",
                            "Cookie: a=b\r\n",
                            "Proxy-Authorization: x\r\n",
                            "Range: bytes=0-3\r\n",
                            "If-None-Match: x\r\n",
                            "Cache-Control: no-store\r\n",
                            "Cache-Control: no-cache\r\n",
                            "Pragma: no-cache\r\n",
                            "Cache-Control: max-age=1, max-age=2\r\n",
                            "Transfer-Encoding: chunked\r\n",
                            "Content-Length: 1\r\n"};
    for (const char* headers : denied) CHECK(!key(headers).eligible);
}
TEST(http_cache, cache_control_age_date_and_vary_are_not_ignored) {
    auto cache = std::make_unique<HttpCache>();
    const char* denied[] = {"Cache-Control: private\r\n",
                            "Content-Length: 4\r\n",
                            "Transfer-Encoding: identity\r\n",
                            "Upgrade: websocket\r\n",
                            "Cache-Control: no-store\r\n",
                            "Cache-Control: no-cache\r\n",
                            "Set-Cookie: a=b\r\n",
                            "Vary: *\r\n",
                            "Vary: Cache-Control\r\n",
                            "Cache-Control: max-age=0\r\n",
                            "Cache-Control: max-age=1, max-age=2\r\n",
                            "Cache-Control: max-age=-1\r\n",
                            "Age: 60\r\n",
                            "Age: 9999999999999999999999999\r\n",
                            "Connection: cache-control\r\n",
                            "Date: invalid\r\n",
                            "Expires: Sun, 25 Oct 2026 00:00:00 GMT\r\n"};
    for (const char* headers : denied) CHECK(!store(*cache, key(), response(headers)));
    REQUIRE(store(*cache, key(), response("Cache-Control: max-age=60, s-maxage=5\r\nAge: 2\r\n")));
    CHECK(lookup(*cache, key(), 3999999) == HttpCache::Result::Hit);
    CHECK(lookup(*cache, key(), 4000000) == HttpCache::Result::Miss);
}
TEST(http_cache, variants_hosts_queries_routes_and_configurations_are_isolated) {
    auto cache = std::make_unique<HttpCache>();
    auto first = key("Accept-Language: en\r\n");
    REQUIRE(store(*cache, first, response("Vary: Accept-Language\r\n")));
    CHECK(lookup(*cache, first, 1000000) == HttpCache::Result::Hit);
    CHECK(lookup(*cache, key("Accept-Language: fr\r\n"), 1000000) == HttpCache::Result::Miss);
    CHECK(lookup(*cache, key("Accept-Language: en\r\n", 2), 1000000) == HttpCache::Result::Miss);
    CHECK(lookup(*cache, key("Accept-Language: en\r\n", 1, "/asset?q=1"), 1000000) ==
          HttpCache::Result::Miss);
    CHECK(lookup(*cache, key("Accept-Language: en\r\n", 1, "/asset", 1), 1000000) ==
          HttpCache::Result::Miss);
    auto collision = key("Accept-Language: xx\r\n");
    collision.hash = first.hash;
    CHECK(lookup(*cache, collision, 1000000) == HttpCache::Result::Miss);
}
TEST(http_cache, request_freshness_and_only_if_cached) {
    auto cache = std::make_unique<HttpCache>();
    REQUIRE(store(*cache, key(), response()));
    CHECK(lookup(*cache, key("Cache-Control: max-age=1\r\n"), 2000001) == HttpCache::Result::Miss);
    CHECK(lookup(*cache, key("Cache-Control: min-fresh=60\r\n"), 1000001) ==
          HttpCache::Result::Miss);
    CHECK(lookup(*cache, key("Cache-Control: only-if-cached\r\n"), 2000000) ==
          HttpCache::Result::Hit);
    CHECK(lookup(*cache, key("Cache-Control: only-if-cached\r\n", 1, "/missing"), 2000000) ==
          HttpCache::Result::OnlyCachedMiss);
}
TEST(http_cache, incomplete_cancelled_evicted_and_invalidated_fills_cannot_publish) {
    auto cache = std::make_unique<HttpCache>();
    u8 out[HttpCache::kMaxResponse];
    u32 written;
    HttpCache::Token token;
    auto request = key();
    REQUIRE(cache->begin(request, 60, 1, true, out, sizeof(out), written, token) ==
            HttpCache::Result::Miss);
    const auto wire = response();
    CHECK(
        !cache->commit(token, reinterpret_cast<const u8*>(wire.data()), wire.size() - 1, 1, kWall));
    REQUIRE(cache->begin(request, 60, 1, true, out, sizeof(out), written, token) ==
            HttpCache::Result::Miss);
    cache->invalidate_host(request.config, request.host);
    CHECK(!cache->commit(token, reinterpret_cast<const u8*>(wire.data()), wire.size(), 1, kWall));
    REQUIRE(cache->begin(request, 60, 1, true, out, sizeof(out), written, token) ==
            HttpCache::Result::Miss);
    cache->cancel(token);
    CHECK(!cache->commit(token, reinterpret_cast<const u8*>(wire.data()), wire.size(), 1, kWall));
    REQUIRE(cache->begin(request, 60, 1, true, out, sizeof(out), written, token) ==
            HttpCache::Result::Miss);
    for (u32 i = 0; i < HttpCache::kCapacity + 1; ++i) {
        auto another = request;
        another.bytes[0] = static_cast<char>(i + 1);
        HttpCache::Token ignored;
        cache->begin(another, 60, 1, true, out, sizeof(out), written, ignored);
    }
    CHECK(!cache->commit(token, reinterpret_cast<const u8*>(wire.data()), wire.size(), 1, kWall));
}
TEST(http_cache, response_delay_ttl_cap_and_overflow) {
    auto cache = std::make_unique<HttpCache>();
    auto request = key();
    u8 out[HttpCache::kMaxResponse];
    u32 written;
    HttpCache::Token token;
    const auto wire = response();
    cache->begin(request, 5, 1000000, true, out, sizeof(out), written, token);
    REQUIRE(cache->commit(
        token, reinterpret_cast<const u8*>(wire.data()), wire.size(), 3500000, kWall));
    CHECK(lookup(*cache, request, 5999999) == HttpCache::Result::Hit);
    CHECK(lookup(*cache, request, 6000000) == HttpCache::Result::Miss);
    cache->begin(request, 60, ~u64{0} - 1, true, out, sizeof(out), written, token);
    CHECK(!cache->commit(
        token, reinterpret_cast<const u8*>(wire.data()), wire.size(), ~u64{0} - 1, kWall));
}
int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
