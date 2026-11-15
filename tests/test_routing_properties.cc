#include "rut/jit/runtime_helpers.h"
#include "rut/runtime/connection.h"
#include "rut/runtime/route_table.h"
#include "rut/runtime/slice_pool.h"
#include "test.h"

using namespace rut;

TEST(routing_properties, transport_identity_and_slot_reset) {
    Connection connection{};
    connection.reset();
    connection.peer_port = 12345;
    connection.listener_context.port = 8443;
    CHECK_EQ(rut_helper_req_connection_scalar(&connection, 0), 12345);
    CHECK_EQ(rut_helper_req_connection_scalar(&connection, 1), 8443);
    CHECK_EQ(rut_helper_req_connection_scalar(&connection, 2), 0);
    connection.tls_active = true;
    CHECK_EQ(rut_helper_req_connection_scalar(&connection, 2), 0);
    connection.tls_handshake_complete = true;
    CHECK_EQ(rut_helper_req_connection_scalar(&connection, 2), 1);
    __builtin_memcpy(connection.tls_server_name, "real.example", 12);
    connection.tls_server_name_length = 12;
    u8 has = 0;
    const char* value = nullptr;
    u32 length = 0;
    rut_helper_req_routing_string(&connection, nullptr, 0, 2, &has, &value, &length);
    CHECK_EQ(has, 1);
    CHECK((Str{value, length}.eq({"real.example", 12})));
    connection.reset();
    rut_helper_req_routing_string(&connection, nullptr, 0, 2, &has, &value, &length);
    CHECK_EQ(has, 0);
    CHECK_EQ(length, 0u);
    CHECK(value == nullptr);
    CHECK_EQ(rut_helper_req_connection_scalar(&connection, 0), 0);
    CHECK_EQ(rut_helper_req_connection_scalar(&connection, 1), 0);
}

TEST(routing_properties, normalized_values_are_owned_and_fail_closed) {
    SlicePool pool;
    REQUIRE(pool.init(8));
    Connection connection{};
    connection.reset();
    connection.json_arena.backend.pool = &pool;
    u8 has = 0;
    const char* value = nullptr;
    u32 length = 0;
    char request[] = "GET /api//x/../%75sers?q=%2f HTTP/1.1\r\nHost: spoof\r\n\r\n";
    rut_helper_req_routing_string(&connection,
                                  reinterpret_cast<const u8*>(request),
                                  sizeof(request) - 1,
                                  1,
                                  &has,
                                  &value,
                                  &length);
    REQUIRE(has == 1);
    CHECK((Str{value, length}.eq({"/api/users?q=%2f", 16})));
    __builtin_memset(request, 'x', sizeof(request));
    CHECK((Str{value, length}.eq({"/api/users?q=%2f", 16})));
    const char* bad = "GET /bad%xx HTTP/1.1\r\nHost: x\r\n\r\n";
    rut_helper_req_routing_string(&connection,
                                  reinterpret_cast<const u8*>(bad),
                                  __builtin_strlen(bad),
                                  0,
                                  &has,
                                  &value,
                                  &length);
    CHECK_EQ(has, 0);
    CHECK(value == nullptr);
    connection.reset();
    CHECK_EQ(pool.count - pool.available(), 0u);
    pool.destroy();
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}

namespace {
u64 host_route_handler(void*, jit::HandlerCtx*, const u8*, u32, void*) {
    return 0;
}
}  // namespace
TEST(routing_properties, host_indexes_preserve_precedence_and_rate_namespaces) {
    RouteConfig config;
    const auto add = [&](const char* path, Str host) {
        return config.add_jit_handler(
            path, kRouteMethodGet, &host_route_handler, false, ForwardPreflightMode::None, 0, host);
    };
    REQUIRE(add("/api", {"a.example", 9}));
    REQUIRE(add("/api", {"b.example", 9}));
    REQUIRE(add("/api", {"*.example", 9}));
    REQUIRE(add("/api", {}));
    CHECK_EQ(config.host_scope_count, 3u);
    const auto select = [&](Str host) {
        return config.match_canonical({"api/x", 5}, kRouteMethodGet, nullptr, nullptr, 0, host);
    };
    CHECK(select({"a.example", 9}) == &config.routes[0]);
    CHECK(select({"b.example", 9}) == &config.routes[1]);
    CHECK(select({"other.example", 13}) == &config.routes[2]);
    CHECK(select({"elsewhere.test", 14}) == &config.routes[3]);
    CHECK(rate_limit_route_id(config.routes[0]) != rate_limit_route_id(config.routes[1]));
    // Match mode stays segment-prefix, including ART scopes.
    CHECK(config.match_canonical(
              {"apix", 4}, kRouteMethodGet, nullptr, nullptr, 0, {"a.example", 9}) == nullptr);
}

TEST(routing_properties, host_authority_is_unambiguous_and_connection_owned) {
    Connection connection{};
    connection.reset();
    ParsedRequest request{};
    request.reset();
    char host[] = "A.EXAMPLE.:8000";
    request.headers[0] = {{"Host", 4}, {host, sizeof(host) - 1}};
    request.header_count = 1;
    REQUIRE(connection.capture_routing_host(request));
    CHECK(connection.routing_host().eq({"a.example", 9}));
    __builtin_memset(host, 'x', sizeof(host));
    CHECK(connection.routing_host().eq({"a.example", 9}));
    request.headers[1] = {{"host", 4}, {"other.example", 13}};
    request.header_count = 2;
    CHECK_FALSE(connection.capture_routing_host(request));
    CHECK_EQ(connection.routing_host().len, 0u);
    char output[254];
    u16 length = 0;
    CHECK_FALSE(route_host_from_authority({"evil@example", 12}, output, &length));
    CHECK_FALSE(route_host_from_authority({"example:65536", 13}, output, &length));
    CHECK_FALSE(route_host_pattern_valid({"a.*.example", 11}));
}
