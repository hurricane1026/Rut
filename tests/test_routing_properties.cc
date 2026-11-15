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
    request.headers[0] = {{"Host", 4}, {host, sizeof(host) - 1}, {}};
    request.header_count = 1;
    REQUIRE(connection.capture_routing_host(request));
    CHECK(connection.routing_host().eq({"a.example", 9}));
    __builtin_memset(host, 'x', sizeof(host));
    CHECK(connection.routing_host().eq({"a.example", 9}));
    request.headers[1] = {{"host", 4}, {"other.example", 13}, {}};
    request.header_count = 2;
    CHECK_FALSE(connection.capture_routing_host(request));
    CHECK_EQ(connection.routing_host().len, 0u);
    char output[254];
    u16 length = 0;
    CHECK_FALSE(route_host_from_authority({"evil@example", 12}, output, &length));
    CHECK_FALSE(route_host_from_authority({"example:65536", 13}, output, &length));
    CHECK_FALSE(route_host_pattern_valid({"a.*.example", 11}));
}

TEST(routing_properties, regex_captures_are_bounded_and_preserve_participation) {
    void* program = rut_helper_regex_capture_compile("^(a+)(b)?()$", 12);
    REQUIRE(program != nullptr);
    struct Cleanup {
        void* handle;
        ~Cleanup() { rut_helper_regex_free(handle); }
    } cleanup{program};
    SlicePool pool;
    REQUIRE(pool.init(32));
    Connection connection{};
    connection.reset();
    connection.json_arena.backend.pool = &pool;
    const char* value = nullptr;
    u32 length = 0;
    CHECK_EQ(rut_helper_regex_capture(&connection, "aaa", 3, program, 1, &value, &length), 1);
    CHECK((Str{value, length}.eq({"aaa", 3})));
    CHECK_EQ(rut_helper_regex_capture(&connection, "aaa", 3, program, 2, &value, &length), 0);
    CHECK(value == nullptr);
    CHECK_EQ(rut_helper_regex_capture(&connection, "aaa", 3, program, 3, &value, &length), 1);
    CHECK_EQ(length, 0u);
    CHECK(value != nullptr);
    connection.reset();
    CHECK_EQ(pool.count - pool.available(), 0u);
    pool.destroy();
}

TEST(routing_properties, regex_capture_serialization_roundtrip_and_compile_bounds) {
    void* program = rut_helper_regex_capture_compile("([a-z]+)-([0-9]+)", 17);
    REQUIRE(program != nullptr);
    char* bytes = nullptr;
    u64 size = 0;
    REQUIRE(rut_helper_regex_serialize(program, &bytes, &size));
    void* restored = rut_helper_regex_deserialize(bytes, size);
    rut_helper_regex_serialized_free(program, bytes, size);
    rut_helper_regex_free(program);
    REQUIRE(restored != nullptr);
    SlicePool pool;
    REQUIRE(pool.init(32));
    Connection connection{};
    connection.reset();
    connection.json_arena.backend.pool = &pool;
    const char* value = nullptr;
    u32 length = 0;
    CHECK_EQ(rut_helper_regex_capture(&connection, "xx a-123 yy", 11, restored, 2, &value, &length),
             1);
    CHECK((Str{value, length}.eq({"123", 3})));
    CHECK_EQ(rut_helper_regex_capture(&connection, "", 0, restored, 9, &value, &length), 2);
    connection.reset();
    pool.destroy();
    rut_helper_regex_free(restored);
    CHECK(rut_helper_regex_capture_compile("(", 1) == nullptr);
    CHECK(rut_helper_regex_capture_compile("()()()()()()()()()", 18) == nullptr);
}

TEST(routing_properties, capture_ambiguous_nonmatch_and_missing_allocator_are_distinct) {
    const char* pattern = "^(a+)+$";
    void* program = rut_helper_regex_capture_compile(pattern, __builtin_strlen(pattern));
    REQUIRE(program != nullptr);
    SlicePool pool;
    REQUIRE(pool.init(8));
    Connection connection{};
    connection.reset();
    connection.json_arena.backend.pool = &pool;
    char subject[129];
    __builtin_memset(subject, 'a', sizeof(subject));
    subject[128] = '!';
    const char* value = nullptr;
    u32 length = 0;
    CHECK_EQ(rut_helper_regex_capture(
                 &connection, subject, sizeof(subject), program, 1, &value, &length),
             0);
    CHECK(value == nullptr);
    CHECK_EQ(length, 0u);
    connection.reset();
    CHECK_EQ(pool.count - pool.available(), 0u);
    // No request allocator is a resource error, never a normal absent capture.
    connection.json_arena.backend.pool = nullptr;
    CHECK_EQ(rut_helper_regex_capture(&connection, "a", 1, program, 1, &value, &length), 2);
    rut_helper_regex_free(program);
    pool.destroy();
}

TEST(routing_properties, host_scopes_accept_ipv6_and_missing_host_global_fallback) {
    char output[254];
    u16 length = 0;
    REQUIRE(route_host_from_authority({"[0:0:0:0:0:0:0:1]:8000", 22}, output, &length));
    CHECK((Str{output, length}.eq({"[::1]", 5})));
    CHECK(route_host_equal({"[0:0:0:0:0:0:0:1]", 17}, {"[::1]", 5}));
    CHECK(route_host_pattern_valid({"[::1]", 5}));
    Connection connection{};
    connection.reset();
    ParsedRequest request{};
    request.reset();
    REQUIRE(connection.capture_routing_host(request));
    CHECK_EQ(connection.routing_host().len, 0u);
    request.header_count = 1;
    request.headers[0] = {{"Host", 4}, {"service~name", 12}, {}};
    CHECK(connection.capture_routing_host(request));
    CHECK_EQ(connection.routing_host().len, 0u);
}
