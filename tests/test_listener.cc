#include "rut/runtime/listener.h"
#include "rut/runtime/listener_context.h"
#include "test.h"
#include <cstddef>
#include <type_traits>

using namespace rut;

TEST(listener, metadata_layout_defaults_and_legacy_aggregates_are_pinned) {
    static_assert(std::is_standard_layout_v<ListenerSpec>);
    static_assert(std::is_trivially_copyable_v<ListenerSpec>);
    static_assert(offsetof(ListenerSpec, address) == 0u);
    static_assert(offsetof(ListenerSpec, transport) == 1u);
    static_assert(offsetof(ListenerSpec, port) == 2u);
    static_assert(offsetof(ListenerSpec, ipv4_host) == 4u);
    static_assert(sizeof(ListenerSpec) == 8u);
    static_assert(alignof(ListenerSpec) == 4u);
    static_assert(std::is_standard_layout_v<ListenerContext>);
    static_assert(std::is_trivially_copyable_v<ListenerContext>);
    static_assert(offsetof(ListenerContext, address) == 0u);
    static_assert(offsetof(ListenerContext, transport) == 1u);
    static_assert(offsetof(ListenerContext, port) == 2u);
    static_assert(offsetof(ListenerContext, ipv4_host) == 4u);
    static_assert(sizeof(ListenerContext) == 8u);
    static_assert(alignof(ListenerContext) == 4u);
    static_assert(static_cast<u8>(ListenerAddress::IPv4Wildcard) == 0u);
    static_assert(static_cast<u8>(ListenerAddress::IPv4Exact) == 1u);

    ListenerSpec defaults{};
    CHECK(defaults.valid());
    CHECK(defaults.address == ListenerAddress::IPv4Wildcard);
    CHECK(defaults.transport == ListenerTransport::Cleartext);
    CHECK_EQ(defaults.port, 8080u);
    CHECK_EQ(defaults.ipv4_host, 0u);

    ListenerSpec legacy_three_field{
        ListenerAddress::IPv4Wildcard, ListenerTransport::Cleartext, static_cast<u16>(9000)};
    CHECK(legacy_three_field.valid());
    CHECK_EQ(legacy_three_field.ipv4_host, 0u);

    ListenerContext legacy_context{
        ListenerAddress::IPv4Wildcard, ListenerTransport::Cleartext, static_cast<u16>(8080)};
    CHECK(legacy_context.valid());
    CHECK_EQ(legacy_context.ipv4_host, 0u);
    ListenerContext exact_context{
        ListenerAddress::IPv4Exact, ListenerTransport::Cleartext, 8080u, 0x7f000001u};
    CHECK(exact_context.valid());
    ListenerContext other_exact = exact_context;
    other_exact.ipv4_host = 0x7f000002u;
    CHECK(!other_exact.equivalent(exact_context));
    exact_context.ipv4_host = 0u;
    CHECK(!exact_context.valid());
    legacy_context.ipv4_host = 0x7f000001u;
    CHECK(!legacy_context.valid());
    legacy_context.address = static_cast<ListenerAddress>(0xff);
    legacy_context.ipv4_host = 0u;
    CHECK(!legacy_context.valid());
}

TEST(listener, source_and_cli_resolution) {
    ListenerSpec source{};
    source.port = 9000;

    auto none = resolve_listener_spec(false, source, false, 0, ListenerTransport::Cleartext);
    REQUIRE(none);
    CHECK_EQ(none.value().port, 8080u);
    CHECK(none.value().address == ListenerAddress::IPv4Wildcard);
    CHECK(none.value().transport == ListenerTransport::Cleartext);
    CHECK_EQ(none.value().ipv4_host, 0u);

    auto source_only = resolve_listener_spec(true, source, false, 0, ListenerTransport::Cleartext);
    REQUIRE(source_only);
    CHECK_EQ(source_only.value().port, 9000u);

    auto cli_only = resolve_listener_spec(false, source, true, 9100, ListenerTransport::Cleartext);
    REQUIRE(cli_only);
    CHECK_EQ(cli_only.value().port, 9100u);
    CHECK(cli_only.value().address == ListenerAddress::IPv4Wildcard);
    CHECK_EQ(cli_only.value().ipv4_host, 0u);

    auto equivalent = resolve_listener_spec(true, source, true, 9000, ListenerTransport::Cleartext);
    REQUIRE(equivalent);
    CHECK_EQ(equivalent.value().port, 9000u);

    auto conflict = resolve_listener_spec(true, source, true, 9100, ListenerTransport::Cleartext);
    CHECK(!conflict);
    if (!conflict) CHECK(conflict.error() == ListenerResolutionError::ConflictingPorts);

    ListenerSpec ephemeral{};
    ephemeral.port = 0;
    auto ephemeral_equivalent =
        resolve_listener_spec(true, ephemeral, true, 0, ListenerTransport::Cleartext);
    REQUIRE(ephemeral_equivalent);
    CHECK_EQ(ephemeral_equivalent.value().port, 0u);
}

TEST(listener, cli_tls_resolution_rejects_source_cleartext) {
    ListenerSpec source{};
    source.port = 8080;

    auto cli_tls = resolve_listener_spec(false, source, false, 0, ListenerTransport::Tls);
    REQUIRE(cli_tls);
    CHECK_EQ(cli_tls.value().port, 8080u);
    CHECK(cli_tls.value().address == ListenerAddress::IPv4Wildcard);
    CHECK(cli_tls.value().transport == ListenerTransport::Tls);
    CHECK_EQ(cli_tls.value().ipv4_host, 0u);

    auto source_and_tls = resolve_listener_spec(true, source, false, 0, ListenerTransport::Tls);
    CHECK(!source_and_tls);
    if (!source_and_tls)
        CHECK(source_and_tls.error() == ListenerResolutionError::ConflictingTransport);
}

TEST(listener, exact_ipv4_resolution_preserves_address_and_rejects_invalid_metadata) {
    ListenerSpec exact{
        ListenerAddress::IPv4Exact, ListenerTransport::Cleartext, 9000u, 0x7f000001u};
    REQUIRE(exact.valid());

    auto source_only = resolve_listener_spec(true, exact, false, 0u, ListenerTransport::Cleartext);
    REQUIRE(source_only);
    CHECK(source_only.value().equivalent(exact));

    auto same_cli_port =
        resolve_listener_spec(true, exact, true, 9000u, ListenerTransport::Cleartext);
    REQUIRE(same_cli_port);
    CHECK(same_cli_port.value().equivalent(exact));

    auto different_cli_port =
        resolve_listener_spec(true, exact, true, 9001u, ListenerTransport::Cleartext);
    REQUIRE_FALSE(different_cli_port);
    CHECK(different_cli_port.error() == ListenerResolutionError::ConflictingPorts);

    auto transport_and_port_conflict =
        resolve_listener_spec(true, exact, true, 9001u, ListenerTransport::Tls);
    REQUIRE_FALSE(transport_and_port_conflict);
    CHECK(transport_and_port_conflict.error() == ListenerResolutionError::ConflictingTransport);

    ListenerSpec exact_ephemeral = exact;
    exact_ephemeral.port = 0u;
    auto ephemeral =
        resolve_listener_spec(true, exact_ephemeral, true, 0u, ListenerTransport::Cleartext);
    REQUIRE(ephemeral);
    CHECK(ephemeral.value().equivalent(exact_ephemeral));

    ListenerSpec same_endpoint_other_address = exact;
    same_endpoint_other_address.ipv4_host = 0x7f000002u;
    CHECK(!same_endpoint_other_address.equivalent(exact));

    const ListenerSpec invalid[] = {
        {ListenerAddress::IPv4Wildcard, ListenerTransport::Cleartext, 9000u, 0x7f000001u},
        {ListenerAddress::IPv4Exact, ListenerTransport::Cleartext, 9000u, 0u},
        {static_cast<ListenerAddress>(0xff), ListenerTransport::Cleartext, 9000u, 0u},
        {ListenerAddress::IPv4Wildcard, static_cast<ListenerTransport>(0xff), 9000u, 0u},
    };
    for (const auto& candidate : invalid) {
        CHECK(!candidate.valid());
        auto result =
            resolve_listener_spec(true, candidate, false, 0u, ListenerTransport::Cleartext);
        REQUIRE_FALSE(result);
        CHECK(result.error() == ListenerResolutionError::InvalidListenerSpec);
    }

    auto invalid_cli = resolve_listener_spec(
        false, ListenerSpec{}, false, 0u, static_cast<ListenerTransport>(0xff));
    REQUIRE_FALSE(invalid_cli);
    CHECK(invalid_cli.error() == ListenerResolutionError::InvalidListenerSpec);
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
