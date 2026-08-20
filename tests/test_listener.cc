#include "rut/runtime/listener.h"
#include "test.h"

using namespace rut;

TEST(listener, source_and_cli_resolution) {
    ListenerSpec source{};
    source.port = 9000;

    auto none = resolve_listener_spec(false, source, false, 0);
    REQUIRE(none);
    CHECK_EQ(none.value().port, 8080u);

    auto source_only = resolve_listener_spec(true, source, false, 0);
    REQUIRE(source_only);
    CHECK_EQ(source_only.value().port, 9000u);

    auto cli_only = resolve_listener_spec(false, source, true, 9100);
    REQUIRE(cli_only);
    CHECK_EQ(cli_only.value().port, 9100u);

    auto equivalent = resolve_listener_spec(true, source, true, 9000);
    REQUIRE(equivalent);
    CHECK_EQ(equivalent.value().port, 9000u);

    auto conflict = resolve_listener_spec(true, source, true, 9100);
    CHECK(!conflict);
    if (!conflict) CHECK(conflict.error() == ListenerResolutionError::ConflictingPorts);

    ListenerSpec ephemeral{};
    ephemeral.port = 0;
    auto ephemeral_equivalent = resolve_listener_spec(true, ephemeral, true, 0);
    REQUIRE(ephemeral_equivalent);
    CHECK_EQ(ephemeral_equivalent.value().port, 0u);
}

int main(int argc, char** argv) { return rut::test::run_all(argc, argv); }
