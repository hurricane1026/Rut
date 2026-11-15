#include "rut/jit/runtime_helpers.h"
#include "rut/runtime/connection.h"
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
