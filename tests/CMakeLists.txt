add_executable(test_framework test_framework.cc)
target_include_directories(test_framework PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/testing
)
add_test(NAME test_framework COMMAND test_framework)
set_tests_properties(test_framework PROPERTIES WILL_FAIL TRUE)
add_test(NAME test_framework_sharding COMMAND test_framework --sharding-self-test)
set_tests_properties(test_framework_sharding PROPERTIES LABELS "unit" TIMEOUT 30)

# Pure #358 Stage 2a1 fixture-worker protocol self-check.  This deliberately
# has no Docker/network label and runs in ordinary CI on an unprivileged host.
add_library(fixture_worker_protocol STATIC fixture_worker_protocol.cc)
target_include_directories(fixture_worker_protocol PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(test_fixture_worker_protocol test_fixture_worker_protocol.cc)
target_link_libraries(test_fixture_worker_protocol PRIVATE fixture_worker_protocol)
add_test(NAME test_fixture_worker_protocol COMMAND test_fixture_worker_protocol)
set_tests_properties(test_fixture_worker_protocol PROPERTIES
    LABELS "unit"
    RUN_SERIAL TRUE
    TIMEOUT 30
)

# Pure bounded IPv4 HTTP exchange/parser self-check. No Docker, nginx, RUT,
# converter, or runtime behavior is involved.
add_executable(test_fixture_bounded_http_exchange
    test_fixture_bounded_http_exchange.cc)
add_library(fixture_bounded_http_exchange STATIC fixture_bounded_http_exchange.cc)
target_compile_definitions(fixture_bounded_http_exchange PRIVATE
    RUT_BOUNDED_HTTP_EXCHANGE_TEST_SEAM)
target_compile_definitions(test_fixture_bounded_http_exchange PRIVATE
    RUT_BOUNDED_HTTP_EXCHANGE_TEST_SEAM)
target_include_directories(fixture_bounded_http_exchange PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(test_fixture_bounded_http_exchange PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(test_fixture_bounded_http_exchange PRIVATE fixture_bounded_http_exchange)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(test_fixture_bounded_http_exchange PRIVATE -fexceptions)
endif()
add_test(NAME test_fixture_bounded_http_exchange
    COMMAND test_fixture_bounded_http_exchange)
set_tests_properties(test_fixture_bounded_http_exchange PROPERTIES
    LABELS "unit"
    RUN_SERIAL TRUE
    TIMEOUT 30)

# Pure #377 CollisionRelease v2 authenticated codec/state machine. The library
# reuses common worker framing but owns no process, listener or runtime state.
add_library(fixture_collision_release_protocol STATIC
    fixture_collision_release_protocol.cc)
target_include_directories(fixture_collision_release_protocol PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(fixture_collision_release_protocol PUBLIC fixture_worker_protocol)

add_executable(test_fixture_collision_release_protocol
    test_fixture_collision_release_protocol.cc)
target_link_libraries(test_fixture_collision_release_protocol PRIVATE
    fixture_collision_release_protocol)
add_test(NAME test_fixture_collision_release_protocol
    COMMAND test_fixture_collision_release_protocol)
set_tests_properties(test_fixture_collision_release_protocol PROPERTIES
    LABELS "unit"
    RUN_SERIAL TRUE
    TIMEOUT 30)

# Pure #377 type-59 Canonical collision/release scalar evidence codec and
# nine-event receiver.  It reuses only the common v1 frame/token transport;
# no broker, process, socket, or runtime target is linked.
add_library(fixture_collision_release_evidence_protocol STATIC
    fixture_collision_release_evidence_protocol.cc)
target_include_directories(fixture_collision_release_evidence_protocol PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(fixture_collision_release_evidence_protocol PUBLIC
    fixture_worker_protocol)

add_executable(test_fixture_collision_release_evidence_protocol
    test_fixture_collision_release_evidence_protocol.cc)
target_link_libraries(test_fixture_collision_release_evidence_protocol PRIVATE
    fixture_collision_release_evidence_protocol)
add_test(NAME test_fixture_collision_release_evidence_protocol
    COMMAND test_fixture_collision_release_evidence_protocol)
set_tests_properties(test_fixture_collision_release_evidence_protocol PROPERTIES
    LABELS "unit"
    RUN_SERIAL TRUE
    TIMEOUT 30)

# Tests-only authenticated absolute-deadline type-59 evidence transport. It
# returns raw frames to the pure evidence codec and owns no broker, process,
# listener, nginx, converter or runtime behavior.
add_library(fixture_collision_release_evidence_transport STATIC
    fixture_collision_release_evidence_transport.cc)
target_include_directories(fixture_collision_release_evidence_transport PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(fixture_collision_release_evidence_transport PUBLIC
    fixture_collision_release_evidence_protocol)

add_executable(test_fixture_collision_release_evidence_transport
    test_fixture_collision_release_evidence_transport.cc)
target_include_directories(test_fixture_collision_release_evidence_transport PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(test_fixture_collision_release_evidence_transport PRIVATE
    fixture_collision_release_evidence_transport)
add_test(NAME test_fixture_collision_release_evidence_transport
    COMMAND test_fixture_collision_release_evidence_transport)
set_tests_properties(test_fixture_collision_release_evidence_transport PROPERTIES
    LABELS "unit"
    RUN_SERIAL TRUE
    TIMEOUT 30)

# Linux-only, tests-only exact raw TCP reservation custody for #377. This owns
# one bound non-listening socket and performs no broker, runtime or RUT work.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_library(fixture_exact_tcp_reservation_lease STATIC
        fixture_exact_tcp_reservation_lease.cc)
    target_include_directories(fixture_exact_tcp_reservation_lease PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR})

    add_executable(test_fixture_exact_tcp_reservation_lease
        test_fixture_exact_tcp_reservation_lease.cc)
    target_link_libraries(test_fixture_exact_tcp_reservation_lease PRIVATE
        fixture_exact_tcp_reservation_lease)
    add_test(NAME test_fixture_exact_tcp_reservation_lease
        COMMAND test_fixture_exact_tcp_reservation_lease)
    set_tests_properties(test_fixture_exact_tcp_reservation_lease PROPERTIES
        LABELS "unit"
        RUN_SERIAL TRUE
        SKIP_RETURN_CODE 77
        TIMEOUT 30)
endif()

# Tests-only identity-bound private /tmp directory custody for #377.
add_library(fixture_private_directory_lease STATIC fixture_private_directory_lease.cc)
target_include_directories(fixture_private_directory_lease PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
add_executable(test_fixture_private_directory_lease test_fixture_private_directory_lease.cc)
target_link_libraries(test_fixture_private_directory_lease PRIVATE fixture_private_directory_lease)
add_test(NAME test_fixture_private_directory_lease COMMAND test_fixture_private_directory_lease)
set_tests_properties(test_fixture_private_directory_lease PROPERTIES
    LABELS "unit" RUN_SERIAL TRUE TIMEOUT 30)

add_library(fixture_exact_input_file_lease STATIC fixture_exact_input_file_lease.cc)
target_include_directories(fixture_exact_input_file_lease PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(fixture_exact_input_file_lease PUBLIC fixture_private_directory_lease)
add_executable(test_fixture_exact_input_file_lease test_fixture_exact_input_file_lease.cc)
target_link_libraries(test_fixture_exact_input_file_lease PRIVATE fixture_exact_input_file_lease)
add_test(NAME test_fixture_exact_input_file_lease COMMAND test_fixture_exact_input_file_lease)
set_tests_properties(test_fixture_exact_input_file_lease PROPERTIES LABELS "unit" TIMEOUT 30)

# Pure #377 paused direct-child lease. This owns only a forked readiness/release
# barrier and pidfd authority; source, log, listener and runtime state remain
# in separately reviewed fixtures.
add_library(fixture_wildcard_paused_child_lease STATIC
    fixture_wildcard_paused_child_lease.cc
)

target_link_libraries(fixture_wildcard_paused_child_lease PRIVATE fixture_worker_protocol)
target_include_directories(fixture_wildcard_paused_child_lease PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(test_fixture_wildcard_paused_child_lease
    test_fixture_wildcard_paused_child_lease.cc
)
target_link_libraries(test_fixture_wildcard_paused_child_lease PRIVATE
    fixture_wildcard_paused_child_lease
)
target_include_directories(test_fixture_wildcard_paused_child_lease PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(test_fixture_wildcard_paused_child_lease PRIVATE -fexceptions)
endif()
add_test(NAME test_fixture_wildcard_paused_child_lease
         COMMAND test_fixture_wildcard_paused_child_lease)
set_tests_properties(test_fixture_wildcard_paused_child_lease PROPERTIES
    LABELS "unit"
    RUN_SERIAL TRUE
    TIMEOUT 30
)

# Tests-only fixed privileged identity bundle transport.  This is a pure
# socketpair/SCM_RIGHTS self-check and is not connected to the broker runtime.
add_library(fixture_identity_bundle STATIC fixture_identity_bundle.cc)
target_include_directories(fixture_identity_bundle PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(test_fixture_identity_bundle test_fixture_identity_bundle.cc)
target_link_libraries(test_fixture_identity_bundle PRIVATE fixture_identity_bundle)
add_test(NAME test_fixture_identity_bundle COMMAND test_fixture_identity_bundle)
set_tests_properties(test_fixture_identity_bundle PROPERTIES
    LABELS "unit"
    RUN_SERIAL TRUE
    TIMEOUT 30
)

# Manifest-free bounded ancestry FD transport.  This remains a pure
# socketpair/procfs self-check and is not connected to the privileged broker.
add_library(fixture_ancestry_bundle STATIC fixture_ancestry_bundle.cc)
target_include_directories(fixture_ancestry_bundle PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(fixture_ancestry_bundle PUBLIC fixture_identity_bundle)

add_executable(test_fixture_ancestry_bundle test_fixture_ancestry_bundle.cc)
target_link_libraries(test_fixture_ancestry_bundle PRIVATE fixture_ancestry_bundle)
add_test(NAME test_fixture_ancestry_bundle COMMAND test_fixture_ancestry_bundle)
set_tests_properties(test_fixture_ancestry_bundle PROPERTIES LABELS "unit" RUN_SERIAL TRUE TIMEOUT 30)

# Pure #358 Stage 2a3b sudo/nsenter/launcher causal state model.  This test
# uses synthetic process identities and never invokes sudo or fakes a positive
# privileged semantic run.
add_library(fixture_direct_launch STATIC fixture_direct_launch.cc)
target_include_directories(fixture_direct_launch PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(test_fixture_direct_launch test_fixture_direct_launch.cc)
target_link_libraries(test_fixture_direct_launch PRIVATE fixture_direct_launch)
add_test(NAME test_fixture_direct_launch COMMAND test_fixture_direct_launch)
set_tests_properties(test_fixture_direct_launch PROPERTIES LABELS "unit" TIMEOUT 30)

# Tests-only retained-sudo ancestry collector and exact one-record binder.
add_library(fixture_privileged_ancestry STATIC fixture_privileged_ancestry.cc)
target_include_directories(fixture_privileged_ancestry PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(fixture_privileged_ancestry PUBLIC
    fixture_ancestry_bundle fixture_direct_launch fixture_identity_bundle fixture_worker_protocol)

add_executable(test_fixture_privileged_ancestry test_fixture_privileged_ancestry.cc)
target_link_libraries(test_fixture_privileged_ancestry PRIVATE fixture_privileged_ancestry)
add_test(NAME test_fixture_privileged_ancestry COMMAND test_fixture_privileged_ancestry)
set_tests_properties(test_fixture_privileged_ancestry PROPERTIES LABELS "unit" RUN_SERIAL TRUE TIMEOUT 30)

# Pure #358 listener plan/source/proc-table/collision-log evidence. The library
# is shared with the privileged broker; this focused unit creates no sockets or
# processes.
add_library(fixture_privileged_listener STATIC fixture_privileged_listener.cc)
target_include_directories(fixture_privileged_listener PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}
)

add_executable(test_fixture_privileged_listener test_fixture_privileged_listener.cc)
target_link_libraries(test_fixture_privileged_listener PRIVATE fixture_privileged_listener)
add_test(NAME test_fixture_privileged_listener COMMAND test_fixture_privileged_listener)
set_tests_properties(test_fixture_privileged_listener PROPERTIES LABELS "unit" TIMEOUT 30)

# Pure #377 immutable wildcard-attempt source identity lease. This focused
# self-check uses only private temporary files and starts no process or socket.
add_library(fixture_wildcard_source_lease STATIC fixture_wildcard_source_lease.cc)
target_include_directories(fixture_wildcard_source_lease PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(fixture_wildcard_source_lease PUBLIC fixture_privileged_listener)

add_executable(test_fixture_wildcard_source_lease test_fixture_wildcard_source_lease.cc)
target_link_libraries(test_fixture_wildcard_source_lease PRIVATE fixture_wildcard_source_lease)
add_test(NAME test_fixture_wildcard_source_lease COMMAND test_fixture_wildcard_source_lease)
set_tests_properties(test_fixture_wildcard_source_lease PROPERTIES LABELS "unit" TIMEOUT 30)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(test_fixture_wildcard_source_reservation_sequence
        test_fixture_wildcard_source_reservation_sequence.cc)
    target_link_libraries(test_fixture_wildcard_source_reservation_sequence PRIVATE
        fixture_wildcard_source_lease
        fixture_exact_tcp_reservation_lease
        fixture_private_directory_lease)
    add_test(NAME test_fixture_wildcard_source_reservation_sequence
        COMMAND test_fixture_wildcard_source_reservation_sequence)
    set_tests_properties(test_fixture_wildcard_source_reservation_sequence PROPERTIES
        LABELS "unit"
        RUN_SERIAL TRUE
        SKIP_RETURN_CODE 77
        TIMEOUT 30)
endif()

# Pure #377 bounded anonymous stdout/stderr capture. This is an unprivileged
# memfd/seals self-check and is not connected to a child, broker or runtime.
add_library(fixture_anonymous_log_capture STATIC fixture_anonymous_log_capture.cc)
target_include_directories(fixture_anonymous_log_capture PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(test_fixture_anonymous_log_capture test_fixture_anonymous_log_capture.cc)
target_link_libraries(test_fixture_anonymous_log_capture PRIVATE fixture_anonymous_log_capture)
add_test(NAME test_fixture_anonymous_log_capture COMMAND test_fixture_anonymous_log_capture)
set_tests_properties(test_fixture_anonymous_log_capture PROPERTIES LABELS "unit" TIMEOUT 30)

# Pure #377 caller-owned executable descriptor/name-binding custody. This
# fixture does not fork, exec, launch a session, open a listener or run RUT.
add_library(fixture_executable_lease STATIC fixture_executable_lease.cc)
target_include_directories(fixture_executable_lease PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(test_fixture_executable_lease test_fixture_executable_lease.cc)
target_link_libraries(test_fixture_executable_lease PRIVATE fixture_executable_lease)
add_test(NAME test_fixture_executable_lease COMMAND test_fixture_executable_lease)
set_tests_properties(test_fixture_executable_lease PROPERTIES
    LABELS "unit"
    RUN_SERIAL TRUE
    TIMEOUT 30)

# Pure #377 executable-OFD child handoff and bounded exec observation.  This
# fixture launches no complete RUT session, listener, broker, or HTTP flow.
add_library(fixture_executable_exec_handoff STATIC
    fixture_executable_exec_handoff.cc)
target_include_directories(fixture_executable_exec_handoff PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(fixture_executable_exec_handoff PUBLIC
    fixture_executable_lease
    fixture_wildcard_paused_child_lease
    fixture_worker_protocol)

add_executable(test_fixture_executable_exec_handoff
    test_fixture_executable_exec_handoff.cc)
target_link_libraries(test_fixture_executable_exec_handoff PRIVATE
    fixture_executable_exec_handoff)
add_test(NAME test_fixture_executable_exec_handoff
    COMMAND test_fixture_executable_exec_handoff)
set_tests_properties(test_fixture_executable_exec_handoff PROPERTIES
    LABELS "unit"
    RUN_SERIAL TRUE
    TIMEOUT 30)

# Reusable tests-only ownership of exactly one public-RUT process attempt. It
# composes lifecycle evidence only; listener/collision/HTTP behavior remains
# outside this fixture.
add_library(fixture_public_rut_session_attempt STATIC
    fixture_public_rut_session_attempt.cc)
target_include_directories(fixture_public_rut_session_attempt PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(fixture_public_rut_session_attempt PUBLIC
    fixture_anonymous_log_capture
    fixture_executable_exec_handoff
    fixture_executable_lease
    fixture_wildcard_paused_child_lease
    fixture_wildcard_source_lease
    fixture_worker_protocol)

add_executable(test_fixture_public_rut_session_attempt
    test_fixture_public_rut_session_attempt.cc)
target_link_libraries(test_fixture_public_rut_session_attempt PRIVATE
    fixture_private_directory_lease
    fixture_public_rut_session_attempt)
add_test(NAME test_fixture_public_rut_session_attempt
    COMMAND test_fixture_public_rut_session_attempt)
set_tests_properties(test_fixture_public_rut_session_attempt PROPERTIES
    LABELS "unit"
    RUN_SERIAL TRUE
    TIMEOUT 30)

# #377 declaration-only paused-child descriptor preparation. This composes the
# independently owned source, capture and child leases only for child dup2/FD
# closure; release remains inert and no runtime/session is launched.
add_executable(test_fixture_wildcard_lease_composition
    test_fixture_wildcard_lease_composition.cc)
target_link_libraries(test_fixture_wildcard_lease_composition PRIVATE
    fixture_anonymous_log_capture
    fixture_wildcard_paused_child_lease
    fixture_wildcard_source_lease
    fixture_worker_protocol)
target_include_directories(test_fixture_wildcard_lease_composition PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR})
add_test(NAME test_fixture_wildcard_lease_composition
    COMMAND test_fixture_wildcard_lease_composition)
set_tests_properties(test_fixture_wildcard_lease_composition PROPERTIES
    LABELS "unit"
    RUN_SERIAL TRUE
    TIMEOUT 30)

if(RUT_ENABLE_JIT)
    # One fresh #377 public-RUT session composing the accepted immutable source,
    # executable, capture, prepared-child and bounded-argv leases. This is a
    # tests-only startup control-plane witness, not a listener/HTTP claim.
    add_executable(test_fixture_wildcard_canonical_session
        test_fixture_wildcard_canonical_session.cc)
    target_link_libraries(test_fixture_wildcard_canonical_session PRIVATE
        fixture_executable_lease
        fixture_private_directory_lease
        fixture_public_rut_session_attempt
        fixture_wildcard_source_lease
        fixture_worker_protocol)
    target_compile_definitions(test_fixture_wildcard_canonical_session PRIVATE
        RUT_SERVER_BINARY="$<TARGET_FILE:rut>")
    add_dependencies(test_fixture_wildcard_canonical_session rut)
    add_test(NAME test_fixture_wildcard_canonical_session
        COMMAND test_fixture_wildcard_canonical_session)
    set_tests_properties(test_fixture_wildcard_canonical_session PROPERTIES
        LABELS "integration;jit;network"
        RUN_SERIAL TRUE
        TIMEOUT 30)

    add_executable(test_fixture_privileged_listener_loader
        test_fixture_privileged_listener_loader.cc)
    target_link_libraries(test_fixture_privileged_listener_loader PRIVATE
        fixture_privileged_listener rut_loader)
    target_include_directories(test_fixture_privileged_listener_loader PRIVATE
        ${LLVM_INCLUDE_DIRS})
    target_compile_definitions(test_fixture_privileged_listener_loader PRIVATE
        ${LLVM_DEFINITIONS} RUT_ENABLE_JIT=1)
    add_test(NAME test_fixture_privileged_listener_loader
        COMMAND test_fixture_privileged_listener_loader)
    set_tests_properties(test_fixture_privileged_listener_loader PROPERTIES
        LABELS "unit;jit" TIMEOUT 30)
endif()

add_executable(test_exact_path_view test_exact_path_view.cc)
target_include_directories(test_exact_path_view PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/testing
)
add_test(NAME test_exact_path_view COMMAND test_exact_path_view)
set_tests_properties(test_exact_path_view PROPERTIES LABELS "unit")

add_executable(test_network
    test_network.cc
    ${PROJECT_SOURCE_DIR}/testing/fault_injection.cc
)
target_link_libraries(test_network rut_runtime)
target_include_directories(test_network PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/testing
    ${CMAKE_CURRENT_SOURCE_DIR}
)
target_compile_definitions(test_network PRIVATE RUT_TESTING=1)
add_test(NAME test_network COMMAND test_network)
set_tests_properties(test_network PROPERTIES LABELS "unit;network")

add_executable(test_target_transform test_target_transform.cc)
target_link_libraries(test_target_transform rut_runtime)
target_include_directories(test_target_transform PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/testing
    ${CMAKE_CURRENT_SOURCE_DIR}
)
add_test(NAME test_target_transform COMMAND test_target_transform)
set_tests_properties(test_target_transform PROPERTIES LABELS "unit")

add_executable(test_redirect_policy test_redirect_policy.cc)
target_link_libraries(test_redirect_policy rut_compiler rut_runtime)
target_include_directories(test_redirect_policy PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/testing
)
add_test(NAME test_redirect_policy COMMAND test_redirect_policy)
set_tests_properties(test_redirect_policy PROPERTIES LABELS "unit")

find_package(Threads REQUIRED)
target_link_libraries(test_fixture_bounded_http_exchange PRIVATE Threads::Threads)
find_package(Python3 REQUIRED COMPONENTS Interpreter)

set(RUT_TLS_TESTDATA_DIR ${CMAKE_CURRENT_BINARY_DIR}/testdata)
set(RUT_TLS_TEST_CERT ${RUT_TLS_TESTDATA_DIR}/localhost_cert.pem)
set(RUT_TLS_TEST_KEY ${RUT_TLS_TESTDATA_DIR}/localhost_key.pem)

file(MAKE_DIRECTORY ${RUT_TLS_TESTDATA_DIR})
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/localhost_cert.pem
    ${RUT_TLS_TEST_CERT}
    COPYONLY
)
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/localhost_key.pem
    ${RUT_TLS_TEST_KEY}
    COPYONLY
)

add_custom_target(test_tls_fixtures DEPENDS ${RUT_TLS_TEST_CERT} ${RUT_TLS_TEST_KEY})

add_executable(test_integration
    test_integration.cc
    epoll_tls_test_hooks.cc
)
target_link_libraries(test_integration
    rut_runtime
    rut_compiler
    Threads::Threads
    ssl
    crypto
)
target_include_directories(test_integration PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/src/runtime
    ${PROJECT_SOURCE_DIR}/testing
    ${CMAKE_CURRENT_SOURCE_DIR}
)
target_compile_definitions(test_integration PRIVATE
    RUT_TESTDATA_DIR="${RUT_TLS_TESTDATA_DIR}"
)
if(RUT_ENABLE_JIT)
    target_link_libraries(test_integration rut_jit rut_loader)
    target_compile_definitions(test_integration PRIVATE RUT_ENABLE_JIT_TESTS=1)
else()
    target_compile_definitions(test_integration PRIVATE RUT_ENABLE_JIT_TESTS=0)
endif()
add_dependencies(test_integration test_tls_fixtures)
add_test(
    NAME test_integration.shard_0_of_2
    COMMAND test_integration --shard-index=0 --shard-count=2)
add_test(
    NAME test_integration.shard_1_of_2
    COMMAND test_integration --shard-index=1 --shard-count=2)
set_tests_properties(
    test_integration.shard_0_of_2
    test_integration.shard_1_of_2
    PROPERTIES
        LABELS "integration;network"
        RESOURCE_LOCK rut_integration
        TIMEOUT 300)

add_executable(test_arena
    test_arena.cc
    ${PROJECT_SOURCE_DIR}/src/placement_new.cc
    ${PROJECT_SOURCE_DIR}/testing/fault_injection.cc
)
target_link_libraries(test_arena rut_runtime)
target_include_directories(test_arena PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/testing
)
add_test(NAME test_arena COMMAND test_arena)
set_tests_properties(test_arena PROPERTIES LABELS "unit")

add_executable(test_expected test_expected.cc ${PROJECT_SOURCE_DIR}/src/placement_new.cc)
target_include_directories(test_expected PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/testing
)
add_test(NAME test_expected COMMAND test_expected)
set_tests_properties(test_expected PROPERTIES LABELS "unit")

add_executable(test_http_parser test_http_parser.cc)
target_link_libraries(test_http_parser rut_runtime)
target_include_directories(test_http_parser PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/testing
    ${CMAKE_CURRENT_SOURCE_DIR}
)
add_test(NAME test_http_parser COMMAND test_http_parser)
set_tests_properties(test_http_parser PROPERTIES LABELS "unit")

add_executable(test_http2 test_http2.cc)
target_link_libraries(test_http2 rut_runtime)
target_include_directories(test_http2 PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/testing
    ${CMAKE_CURRENT_SOURCE_DIR}
)
add_test(NAME test_http2 COMMAND test_http2)
set_tests_properties(test_http2 PROPERTIES LABELS "unit")

add_executable(test_hpack test_hpack.cc)
target_link_libraries(test_hpack rut_runtime)
target_include_directories(test_hpack PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/testing
    ${CMAKE_CURRENT_SOURCE_DIR}
)
add_test(NAME test_hpack COMMAND test_hpack)
set_tests_properties(test_hpack PROPERTIES LABELS "unit")

# RFC 6455 WebSocket frame codec (src/runtime/ws_frame.cc).
add_executable(test_ws_frame test_ws_frame.cc)
target_link_libraries(test_ws_frame rut_runtime)
target_include_directories(test_ws_frame PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/testing
    ${CMAKE_CURRENT_SOURCE_DIR}
)
add_test(NAME test_ws_frame COMMAND test_ws_frame)
set_tests_properties(test_ws_frame PROPERTIES LABELS "unit")

# WebSocket terminate-mode inspection engine (src/runtime/ws_terminate.cc).
add_executable(test_ws_terminate test_ws_terminate.cc)
target_link_libraries(test_ws_terminate rut_runtime)
target_include_directories(test_ws_terminate PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/testing
    ${CMAKE_CURRENT_SOURCE_DIR}
)
add_test(NAME test_ws_terminate COMMAND test_ws_terminate)
set_tests_properties(test_ws_terminate PROPERTIES LABELS "unit")

# Differential HPACK test against the vendored nghttp2 reference.
add_executable(test_hpack_diff test_hpack_diff.cc)
target_link_libraries(test_hpack_diff rut_runtime nghttp2_ref)
target_include_directories(test_hpack_diff PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/testing
    ${CMAKE_CURRENT_SOURCE_DIR}
)
add_test(NAME test_hpack_diff COMMAND test_hpack_diff)
set_tests_properties(test_hpack_diff PROPERTIES LABELS "unit")

add_executable(test_http2_conn test_http2_conn.cc)
target_link_libraries(test_http2_conn rut_runtime)
target_include_directories(test_http2_conn PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/testing
    ${CMAKE_CURRENT_SOURCE_DIR}
)
add_test(NAME test_http2_conn COMMAND test_http2_conn)
set_tests_properties(test_http2_conn PROPERTIES LABELS "unit")

add_executable(test_chunked_parser test_chunked_parser.cc)
target_link_libraries(test_chunked_parser rut_runtime)
target_include_directories(test_chunked_parser PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/testing
    ${CMAKE_CURRENT_SOURCE_DIR}
)
add_test(NAME test_chunked_parser COMMAND test_chunked_parser)
set_tests_properties(test_chunked_parser PROPERTIES LABELS "unit")

add_executable(test_buffer test_buffer.cc)
target_include_directories(test_buffer PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/testing
)
add_test(NAME test_buffer COMMAND test_buffer)
set_tests_properties(test_buffer PROPERTIES LABELS "unit")

add_executable(test_cache_table test_cache_table.cc)
target_include_directories(test_cache_table PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/testing
)
add_test(NAME test_cache_table COMMAND test_cache_table)
set_tests_properties(test_cache_table PROPERTIES LABELS "unit")

add_executable(test_types test_types.cc)
target_include_directories(test_types PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/testing
)
add_test(NAME test_types COMMAND test_types)
set_tests_properties(test_types PROPERTIES LABELS "unit")

add_executable(test_route_trie test_route_trie.cc)
target_link_libraries(test_route_trie rut_runtime)
target_include_directories(test_route_trie PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/testing
)
add_test(NAME test_route_trie COMMAND test_route_trie)
set_tests_properties(test_route_trie PROPERTIES LABELS "unit")

add_executable(test_route_art test_route_art.cc)
target_link_libraries(test_route_art rut_runtime)
target_include_directories(test_route_art PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/testing
)
add_test(NAME test_route_art COMMAND test_route_art)
set_tests_properties(test_route_art PROPERTIES LABELS "unit")

add_executable(test_route_select test_route_select.cc)
target_link_libraries(test_route_select rut_runtime)
target_include_directories(test_route_select PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/testing
)
add_test(NAME test_route_select COMMAND test_route_select)
set_tests_properties(test_route_select PROPERTIES LABELS "unit")

add_executable(test_rir test_rir.cc ${PROJECT_SOURCE_DIR}/src/placement_new.cc)
target_link_libraries(test_rir rut_compiler)
target_include_directories(test_rir PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/testing
)
add_test(NAME test_rir COMMAND test_rir)
set_tests_properties(test_rir PROPERTIES LABELS "unit")

add_executable(test_frontend test_frontend.cc ${PROJECT_SOURCE_DIR}/src/placement_new.cc)
target_link_libraries(test_frontend rut_compiler rut_runtime)
target_include_directories(test_frontend PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/testing
)
add_test(NAME test_frontend COMMAND test_frontend)
set_tests_properties(test_frontend PROPERTIES LABELS "unit;compiler")

add_executable(test_listener test_listener.cc ${PROJECT_SOURCE_DIR}/src/placement_new.cc)
target_include_directories(test_listener PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/testing
)
add_test(NAME test_listener COMMAND test_listener)
set_tests_properties(test_listener PROPERTIES LABELS "unit;runtime")

add_executable(test_nginx_parser test_nginx_parser.cc)
target_link_libraries(test_nginx_parser rut_nginx rut_compiler rut_runtime)
target_include_directories(test_nginx_parser PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/testing
)
add_test(NAME test_nginx_parser COMMAND test_nginx_parser)
set_tests_properties(test_nginx_parser PROPERTIES LABELS "unit;nginx;compiler")

add_executable(test_drain test_drain.cc)
target_link_libraries(test_drain rut_runtime)
target_include_directories(test_drain PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/testing
    ${CMAKE_CURRENT_SOURCE_DIR}
)
add_test(NAME test_drain COMMAND test_drain)
set_tests_properties(test_drain PROPERTIES LABELS "unit")

add_executable(test_access_log
    test_access_log.cc
    ${PROJECT_SOURCE_DIR}/testing/fault_injection.cc
)
find_library(RUT_TEST_ZSTD_DECOMPRESS_LIBRARY NAMES zstd REQUIRED)
add_executable(test_access_log_zstd_decompress_helper zstd_decompress_helper.cc)
target_include_directories(test_access_log_zstd_decompress_helper PRIVATE
    ${PROJECT_SOURCE_DIR}/third_party/zstd/lib
)
target_link_libraries(test_access_log_zstd_decompress_helper
    ${RUT_TEST_ZSTD_DECOMPRESS_LIBRARY}
)
target_link_libraries(test_access_log rut_runtime)
target_compile_definitions(test_access_log PRIVATE
    RUT_TEST_ZSTD_DECOMPRESS_HELPER="$<TARGET_FILE:test_access_log_zstd_decompress_helper>"
)
add_dependencies(test_access_log test_access_log_zstd_decompress_helper)
target_include_directories(test_access_log PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/testing
    ${CMAKE_CURRENT_SOURCE_DIR}
)
add_test(NAME test_access_log COMMAND test_access_log)
set_tests_properties(test_access_log PROPERTIES LABELS "unit")

add_executable(test_access_log_live test_access_log_live.cc)
target_link_libraries(test_access_log_live rut_runtime)
target_include_directories(test_access_log_live PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/testing
)
add_test(NAME test_access_log_live COMMAND test_access_log_live)
set_tests_properties(test_access_log_live PROPERTIES LABELS "unit;runtime" TIMEOUT 30)

add_executable(test_access_log_live_writer
    test_access_log_live_writer.cc
    ${PROJECT_SOURCE_DIR}/testing/fault_injection.cc
)
target_link_libraries(test_access_log_live_writer rut_runtime)
target_include_directories(test_access_log_live_writer PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/testing
)
add_test(NAME test_access_log_live_writer COMMAND test_access_log_live_writer)
set_tests_properties(test_access_log_live_writer PROPERTIES LABELS "unit;runtime" TIMEOUT 30)

add_executable(test_access_log_live_producer
    test_access_log_live_producer.cc
    ${PROJECT_SOURCE_DIR}/testing/fault_injection.cc
)
target_link_libraries(test_access_log_live_producer rut_runtime)
target_include_directories(test_access_log_live_producer PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/testing
)
add_test(NAME test_access_log_live_producer COMMAND test_access_log_live_producer)
set_tests_properties(test_access_log_live_producer PROPERTIES LABELS "unit;runtime" TIMEOUT 30)

add_executable(test_access_log_startup test_access_log_startup.cc)
target_link_libraries(test_access_log_startup rut_runtime)
target_include_directories(test_access_log_startup PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/testing
)
target_compile_definitions(test_access_log_startup PRIVATE
    RUT_ACCESS_LOG_STARTUP_PROCESS_TEST=1
    RUT_SERVER_BINARY="$<TARGET_FILE:rut>"
)
add_dependencies(test_access_log_startup rut)
if(RUT_ENABLE_JIT)
    target_compile_definitions(test_access_log_startup PRIVATE
        RUT_ACCESS_LOG_STARTUP_SOURCE_PROCESS_TEST=1
    )
endif()
add_test(NAME test_access_log_startup COMMAND test_access_log_startup)
set_tests_properties(test_access_log_startup PROPERTIES LABELS "unit;runtime" TIMEOUT 30)

add_executable(test_metrics test_metrics.cc)
target_link_libraries(test_metrics rut_runtime)
target_include_directories(test_metrics PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/testing
    ${CMAKE_CURRENT_SOURCE_DIR}
)
add_test(NAME test_metrics COMMAND test_metrics)
set_tests_properties(test_metrics PROPERTIES LABELS "unit")

add_executable(test_debug test_debug.cc)
target_link_libraries(test_debug rut_runtime)
target_include_directories(test_debug PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/testing
    ${CMAKE_CURRENT_SOURCE_DIR}
)
add_test(NAME test_debug COMMAND test_debug)
set_tests_properties(test_debug PROPERTIES LABELS "unit")

add_executable(test_fault_injection
    test_fault_injection.cc
    ${PROJECT_SOURCE_DIR}/testing/fault_injection.cc
)
target_link_libraries(test_fault_injection rut_runtime)
target_include_directories(test_fault_injection PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/testing
    ${CMAKE_CURRENT_SOURCE_DIR}
)
add_test(NAME test_fault_injection COMMAND test_fault_injection)
set_tests_properties(test_fault_injection PROPERTIES LABELS "unit")

add_executable(test_shard_control test_shard_control.cc)
target_link_libraries(test_shard_control rut_runtime Threads::Threads)
target_include_directories(test_shard_control PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/testing
    ${CMAKE_CURRENT_SOURCE_DIR}
)
add_test(NAME test_shard_control COMMAND test_shard_control)
set_tests_properties(test_shard_control PROPERTIES LABELS "unit")

if(RUT_ENABLE_JIT)
    set(_RUT_PINNED_NGINX_IMAGE_FILE "${CMAKE_CURRENT_SOURCE_DIR}/pinned-nginx-image.txt")
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
        "${_RUT_PINNED_NGINX_IMAGE_FILE}"
    )
    file(STRINGS "${_RUT_PINNED_NGINX_IMAGE_FILE}" _RUT_PINNED_NGINX_IMAGE_LINES
         LIMIT_COUNT 2)
    file(SIZE "${_RUT_PINNED_NGINX_IMAGE_FILE}" _RUT_PINNED_NGINX_IMAGE_FILE_SIZE)
    list(LENGTH _RUT_PINNED_NGINX_IMAGE_LINES _RUT_PINNED_NGINX_IMAGE_LINE_COUNT)
    if(NOT _RUT_PINNED_NGINX_IMAGE_LINE_COUNT EQUAL 1 OR
       NOT _RUT_PINNED_NGINX_IMAGE_FILE_SIZE EQUAL 78)
        message(FATAL_ERROR
            "${_RUT_PINNED_NGINX_IMAGE_FILE} must contain exactly one newline-terminated image reference"
        )
    endif()
    list(GET _RUT_PINNED_NGINX_IMAGE_LINES 0 _RUT_PINNED_NGINX_IMAGE)
    string(LENGTH "${_RUT_PINNED_NGINX_IMAGE}" _RUT_PINNED_NGINX_IMAGE_LENGTH)
    if(NOT _RUT_PINNED_NGINX_IMAGE_LENGTH EQUAL 77 OR
       NOT _RUT_PINNED_NGINX_IMAGE MATCHES "^nginx@sha256:[0-9a-f]+$")
        message(FATAL_ERROR
            "${_RUT_PINNED_NGINX_IMAGE_FILE} must contain nginx@sha256: followed by exactly 64 lowercase hexadecimal characters"
        )
    endif()

    add_library(test_nginx_downstream_gate_preload SHARED nginx_downstream_gate_preload.c)
    target_include_directories(test_nginx_downstream_gate_preload PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
    )
    target_link_libraries(test_nginx_downstream_gate_preload PRIVATE dl)

    if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64)$")
        add_library(test_rut_iouring_gate_preload SHARED rut_iouring_gate_preload.c)
        target_include_directories(test_rut_iouring_gate_preload PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}
        )
        target_link_libraries(test_rut_iouring_gate_preload PRIVATE Threads::Threads)
    endif()

    add_executable(test_nginx_differential test_nginx_differential.cc
                   ${PROJECT_SOURCE_DIR}/src/placement_new.cc)
    target_link_libraries(test_nginx_differential PRIVATE rut_nginx rut_loader Threads::Threads)
    target_include_directories(test_nginx_differential PRIVATE
        ${PROJECT_SOURCE_DIR}/include
    )
    target_compile_definitions(test_nginx_differential PRIVATE
        "RUT_PINNED_NGINX_IMAGE=\"${_RUT_PINNED_NGINX_IMAGE}\""
    )
    add_dependencies(test_nginx_differential rut test_nginx_downstream_gate_preload)
    if(TARGET test_rut_iouring_gate_preload)
        add_dependencies(test_nginx_differential test_rut_iouring_gate_preload)
    endif()
    add_executable(test_ipv4_fixture_topology
        test_ipv4_fixture_topology.cc
        fixture_ipv4_topology.cc
    )
    target_link_libraries(test_ipv4_fixture_topology PRIVATE
        fixture_bounded_http_exchange
        fixture_exact_input_file_lease
        fixture_private_directory_lease
        fixture_privileged_listener
    )
    target_compile_definitions(test_ipv4_fixture_topology PRIVATE
        "RUT_PINNED_NGINX_IMAGE=\"${_RUT_PINNED_NGINX_IMAGE}\""
    )
    add_test(NAME test_ipv4_fixture_topology COMMAND test_ipv4_fixture_topology)
    set_tests_properties(test_ipv4_fixture_topology PROPERTIES
        LABELS "integration;docker;network"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 120
        SKIP_RETURN_CODE 77
    )
    add_executable(test_fixture_privileged_broker
        test_fixture_privileged_broker.cc
        fixture_ipv4_topology.cc
        ${PROJECT_SOURCE_DIR}/src/placement_new.cc
    )
    target_link_libraries(test_fixture_privileged_broker PRIVATE
        rut_nginx
        fixture_bounded_http_exchange
        fixture_ancestry_bundle
        fixture_collision_release_evidence_protocol
        fixture_collision_release_evidence_transport
        fixture_collision_release_protocol
        fixture_direct_launch
        fixture_exact_tcp_reservation_lease
        fixture_exact_input_file_lease
        fixture_executable_exec_handoff
        fixture_executable_lease
        fixture_identity_bundle
        fixture_private_directory_lease
        fixture_privileged_ancestry
        fixture_privileged_listener
        fixture_public_rut_session_attempt
        fixture_worker_protocol
        fixture_wildcard_paused_child_lease
        fixture_wildcard_source_lease
    )
    target_include_directories(test_fixture_privileged_broker PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${PROJECT_SOURCE_DIR}/include
    )
    target_compile_definitions(test_fixture_privileged_broker PRIVATE
        "RUT_PINNED_NGINX_IMAGE=\"${_RUT_PINNED_NGINX_IMAGE}\""
    )
    add_dependencies(test_fixture_privileged_broker rut)
    add_test(NAME test_fixture_privileged_broker
             COMMAND test_fixture_privileged_broker $<TARGET_FILE:rut>)
    add_test(NAME test_fixture_generated_nginx_differential
             COMMAND test_fixture_privileged_broker
                     $<TARGET_FILE:rut>
                     --generated-nginx-differential)

    add_executable(test_fixture_exact_input_mount_owner
        test_fixture_exact_input_mount_owner.cc
        fixture_ipv4_topology.cc
    )
    target_link_libraries(test_fixture_exact_input_mount_owner PRIVATE
        fixture_bounded_http_exchange
        fixture_exact_input_file_lease
        fixture_private_directory_lease
        fixture_privileged_listener
        Threads::Threads
    )
    target_compile_definitions(test_fixture_exact_input_mount_owner PRIVATE
        "RUT_PINNED_NGINX_IMAGE=\"${_RUT_PINNED_NGINX_IMAGE}\""
    )
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        # This shared tests-only source deliberately accepts throwing callbacks
        # and catches them before they can escape into the fixture controller.
        foreach(_target IN ITEMS
                test_ipv4_fixture_topology
                test_fixture_privileged_broker
                test_fixture_exact_input_mount_owner)
            target_compile_options(${_target} PRIVATE -fexceptions)
        endforeach()
    endif()
    add_test(NAME test_fixture_exact_input_mount_owner
             COMMAND test_fixture_exact_input_mount_owner)
    set_tests_properties(test_fixture_exact_input_mount_owner PROPERTIES
        LABELS "integration;docker;network"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 360
        SKIP_RETURN_CODE 77
    )
    add_test(NAME test_fixture_exact_input_read_runner
             COMMAND test_fixture_exact_input_mount_owner
                     --exact-input-read-runner-self-check)
    set_tests_properties(test_fixture_exact_input_read_runner PROPERTIES
        LABELS "unit"
        TIMEOUT 30
    )
    set(_RUT_PRIVILEGED_BROKER_TIMEOUT_SECONDS 360)
    set_tests_properties(test_fixture_privileged_broker PROPERTIES
        LABELS "integration;docker;network"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT ${_RUT_PRIVILEGED_BROKER_TIMEOUT_SECONDS}
        SKIP_RETURN_CODE 77
    )
    set_tests_properties(test_fixture_generated_nginx_differential PROPERTIES
        LABELS "integration;docker;network;differential"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT ${_RUT_PRIVILEGED_BROKER_TIMEOUT_SECONDS}
        SKIP_RETURN_CODE 77
    )
    add_test(NAME test_fixture_wildcard_attempt_protocol
             COMMAND test_fixture_privileged_broker
                     --wildcard-attempt-protocol-self-check)
    set_tests_properties(test_fixture_wildcard_attempt_protocol PROPERTIES
        LABELS "unit"
    )
    add_test(NAME test_fixture_canonical_wait_strategy
             COMMAND test_fixture_privileged_broker
                     --canonical-wait-strategy-self-check)
    set_tests_properties(test_fixture_canonical_wait_strategy PROPERTIES
        LABELS "unit"
        TIMEOUT 30
    )
    add_test(NAME test_fixture_canonical_target_cleanup
             COMMAND test_fixture_privileged_broker
                     --canonical-target-cleanup-self-check)
    set_tests_properties(test_fixture_canonical_target_cleanup PROPERTIES
        LABELS "integration;network"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 60
        SKIP_RETURN_CODE 77
    )
    add_test(
        NAME test_nginx_downstream_gate_spike
        COMMAND test_nginx_differential --nginx-gate-spike
                $<TARGET_FILE:test_nginx_downstream_gate_preload>
    )
    set_tests_properties(test_nginx_downstream_gate_spike PROPERTIES
        LABELS "integration;nginx;docker"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 60
        SKIP_RETURN_CODE 77
    )
    add_test(
        NAME test_nginx_coalesced_ingress_gate
        COMMAND test_nginx_differential --nginx-coalesced-ingress-gate
                $<TARGET_FILE:test_nginx_downstream_gate_preload>
    )
    set_tests_properties(test_nginx_coalesced_ingress_gate PROPERTIES
        LABELS "integration;nginx;docker"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 60
        SKIP_RETURN_CODE 77
    )
    add_test(
        NAME test_nginx_exact_local_return_baseline
        COMMAND test_nginx_differential --exact-local-return-baseline
    )
    set_tests_properties(test_nginx_exact_local_return_baseline PROPERTIES
        LABELS "integration;nginx;docker"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 60
        SKIP_RETURN_CODE 77
    )
    add_test(
        NAME test_nginx_exact_local_return204_oracle
        COMMAND test_nginx_differential --exact-local-return204-oracle
    )
    set_tests_properties(test_nginx_exact_local_return204_oracle PROPERTIES
        LABELS "integration;nginx;docker"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 90
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_exact_local_return204_query_oracle
        COMMAND test_nginx_differential --exact-local-return204-query-oracle
    )
    set_tests_properties(test_nginx_exact_local_return204_query_oracle PROPERTIES
        LABELS "integration;nginx;docker"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 90
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_root_proxy_trace_oracle
        COMMAND test_nginx_differential --root-proxy-trace-oracle
    )
    set_tests_properties(test_nginx_root_proxy_trace_oracle PROPERTIES
        LABELS "integration;nginx;docker"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 60
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_api_proxy_trace_oracle
        COMMAND test_nginx_differential --api-proxy-trace-oracle
    )
    set_tests_properties(test_nginx_api_proxy_trace_oracle PROPERTIES
        LABELS "integration;nginx;docker"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 60
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_exact_absolute_redirect_oracle
        COMMAND test_nginx_differential --exact-absolute-redirect-oracle
    )
    set_tests_properties(test_nginx_exact_absolute_redirect_oracle PROPERTIES
        LABELS "integration;nginx;docker"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 60
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_exact_absolute_redirect_302_oracle
        COMMAND test_nginx_differential --exact-absolute-redirect-302-oracle
    )
    set_tests_properties(test_nginx_exact_absolute_redirect_302_oracle PROPERTIES
        LABELS "integration;nginx;docker"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 60
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_api_non_root_proxy_uri_oracle
        COMMAND test_nginx_differential --api-non-root-proxy-uri-oracle
    )
    set_tests_properties(test_nginx_api_non_root_proxy_uri_oracle PROPERTIES
        LABELS "integration;nginx;docker"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 60
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_service_root_proxy_uri_oracle
        COMMAND test_nginx_differential --service-root-proxy-uri-oracle
    )
    set_tests_properties(test_nginx_service_root_proxy_uri_oracle PROPERTIES
        LABELS "integration;nginx;docker"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 60
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue357_wildcard_service_no_uri_oracle
        COMMAND test_nginx_differential --pinned-nginx-wildcard-service-no-uri-oracle
    )
    set_tests_properties(test_nginx_issue357_wildcard_service_no_uri_oracle PROPERTIES
        LABELS "integration;nginx;docker"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 180
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_pinned_static_query_proxy_uri_oracle
        COMMAND test_nginx_differential --pinned-nginx-static-query-proxy-uri-oracle
    )
    set_tests_properties(test_nginx_pinned_static_query_proxy_uri_oracle PROPERTIES
        LABELS "integration;nginx;docker"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 90
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue341_zero_suffix_static_query_proxy_oracle
        COMMAND test_nginx_differential --pinned-nginx-zero-suffix-static-query-proxy-uri-oracle
    )
    set_tests_properties(test_nginx_issue341_zero_suffix_static_query_proxy_oracle PROPERTIES
        LABELS "integration;nginx;docker"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 90
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue360_empty_configured_query_oracle
        COMMAND test_nginx_differential --pinned-nginx-empty-query-proxy-uri-oracle
    )
    set_tests_properties(test_nginx_issue360_empty_configured_query_oracle PROPERTIES
        LABELS "integration;nginx;docker"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 120
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue372_root_empty_query_proxy_uri_oracle
        COMMAND test_nginx_differential --pinned-nginx-root-empty-query-proxy-uri-oracle
    )
    set_tests_properties(test_nginx_issue372_root_empty_query_proxy_uri_oracle PROPERTIES
        LABELS "integration;nginx;docker"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 120
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue373_proxy_hide_header_oracle
        COMMAND test_nginx_differential --pinned-nginx-proxy-hide-header-oracle
    )
    set_tests_properties(test_nginx_issue373_proxy_hide_header_oracle PROPERTIES
        LABELS "integration;nginx;docker"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 90
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue439_pinned_lifecycle_self_check
        COMMAND test_nginx_differential --pinned-nginx-lifecycle-self-check
    )
    set_tests_properties(test_nginx_issue439_pinned_lifecycle_self_check PROPERTIES
        LABELS "nginx"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 30
    )
    add_test(
        NAME test_nginx_zero_response_stall_self_check
        COMMAND test_nginx_differential --zero-response-stall-self-check
    )
    set_tests_properties(test_nginx_zero_response_stall_self_check PROPERTIES
        LABELS "network"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 30
    )
    add_test(
        NAME test_nginx_issue373_converter_proxy_hide_header_source_self_check
        COMMAND test_nginx_differential --converter-proxy-hide-header-source-self-check
    )
    set_tests_properties(test_nginx_issue373_converter_proxy_hide_header_source_self_check PROPERTIES
        LABELS "nginx"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 30
    )
    add_test(
        NAME test_nginx_issue270_converter_explicit_timeout_head_source_self_check
        COMMAND test_nginx_differential --converter-explicit-timeout-head-source-self-check
    )
    set_tests_properties(test_nginx_issue270_converter_explicit_timeout_head_source_self_check PROPERTIES
        LABELS "nginx"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 30
    )
    add_test(
        NAME test_nginx_issue270_converter_explicit_timeout_head_generated_episode
        COMMAND test_nginx_differential --converter-explicit-timeout-head-generated-episode $<TARGET_FILE:rut>
    )
    set_tests_properties(test_nginx_issue270_converter_explicit_timeout_head_generated_episode PROPERTIES
        LABELS "integration;io_uring;network"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 30
    )
    add_test(
        NAME test_nginx_issue268_explicit_timeout_head_phase_differential
        COMMAND test_nginx_differential --explicit-timeout-head-phase-differential $<TARGET_FILE:rut>
    )
    set_tests_properties(test_nginx_issue268_explicit_timeout_head_phase_differential PROPERTIES
        LABELS "integration;io_uring;network;nginx;docker"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 180
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue270_keepalive_timeout_head_differential
        COMMAND test_nginx_differential --keepalive-timeout-head-differential $<TARGET_FILE:rut>
    )
    set_tests_properties(test_nginx_issue270_keepalive_timeout_head_differential PROPERTIES
        LABELS "integration;io_uring;network;nginx;docker;differential"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 180
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue270_keepalive_timeout_get_initial_deadline_differential
        COMMAND test_nginx_differential --keepalive-timeout-get-initial-deadline-differential $<TARGET_FILE:rut>
    )
    set_tests_properties(test_nginx_issue270_keepalive_timeout_get_initial_deadline_differential PROPERTIES
        LABELS "integration;io_uring;network;nginx;docker;differential"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 180
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue270_fixed_upload_head_success_differential
        COMMAND test_nginx_differential --fixed-upload-head-success-differential $<TARGET_FILE:rut>
    )
    set_tests_properties(test_nginx_issue270_fixed_upload_head_success_differential PROPERTIES
        LABELS "integration;io_uring;network;nginx;docker;differential"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 180
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue270_fixed_upload_head_zero_response_timeout_differential
        COMMAND test_nginx_differential --fixed-upload-head-zero-response-timeout-differential $<TARGET_FILE:rut>
    )
    set_tests_properties(test_nginx_issue270_fixed_upload_head_zero_response_timeout_differential PROPERTIES
        LABELS "integration;io_uring;network;nginx;docker;differential"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 180
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue270_fixed_upload_head_incomplete_progress_timeout_differential
        COMMAND test_nginx_differential --fixed-upload-head-incomplete-progress-timeout-differential $<TARGET_FILE:rut>
    )
    set_tests_properties(test_nginx_issue270_fixed_upload_head_incomplete_progress_timeout_differential PROPERTIES
        LABELS "integration;io_uring;network;nginx;docker;differential"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 180
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue270_fixed_upload_head_two_incomplete_header_fragments_timeout_differential
        COMMAND test_nginx_differential --fixed-upload-head-two-incomplete-header-fragments-timeout-differential $<TARGET_FILE:rut>
    )
    set_tests_properties(test_nginx_issue270_fixed_upload_head_two_incomplete_header_fragments_timeout_differential PROPERTIES
        LABELS "integration;io_uring;network;nginx;docker;differential"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 180
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue373_converter_proxy_hide_header_generated_side_self_check
        COMMAND test_nginx_differential --converter-proxy-hide-header-generated-side-self-check $<TARGET_FILE:rut>
    )
    set_tests_properties(test_nginx_issue373_converter_proxy_hide_header_generated_side_self_check PROPERTIES
        LABELS "integration;io_uring;network;nginx"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 90
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue373_converter_proxy_hide_header_generated_pair_self_check
        COMMAND test_nginx_differential --converter-proxy-hide-header-generated-pair-self-check $<TARGET_FILE:rut>
    )
    set_tests_properties(test_nginx_issue373_converter_proxy_hide_header_generated_pair_self_check PROPERTIES
        LABELS "integration;io_uring;network;nginx"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 120
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue373_converter_proxy_hide_header_differential
        COMMAND test_nginx_differential --converter-proxy-hide-header-differential $<TARGET_FILE:rut>
    )
    set_tests_properties(test_nginx_issue373_converter_proxy_hide_header_differential PROPERTIES
        LABELS "integration;nginx;docker;io_uring;network"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 240
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue271_converter_default_buffering_positive_get_differential
        COMMAND test_nginx_differential
                --converter-default-buffering-positive-get-differential $<TARGET_FILE:rut>
    )
    set_tests_properties(
        test_nginx_issue271_converter_default_buffering_positive_get_differential PROPERTIES
        LABELS "integration;nginx;docker;io_uring;network"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 120
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue271_converter_default_buffering_incomplete_clean_eof_differential
        COMMAND test_nginx_differential
                --converter-default-buffering-incomplete-clean-eof-differential $<TARGET_FILE:rut>
    )
    set_tests_properties(
        test_nginx_issue271_converter_default_buffering_incomplete_clean_eof_differential PROPERTIES
        LABELS "integration;nginx;docker;io_uring;network;differential"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 180
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue271_converter_default_buffering_incomplete_body_inactivity_expiry_differential
        COMMAND test_nginx_differential
                --converter-default-buffering-incomplete-body-inactivity-expiry-differential
                $<TARGET_FILE:rut>
    )
    set_tests_properties(
        test_nginx_issue271_converter_default_buffering_incomplete_body_inactivity_expiry_differential
        PROPERTIES
        LABELS "integration;nginx;docker;io_uring;network;differential"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 180
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue271_converter_default_buffering_second_body_progress_refresh_differential
        COMMAND test_nginx_differential
                --converter-default-buffering-second-body-progress-refresh-differential
                $<TARGET_FILE:rut>
    )
    set_tests_properties(
        test_nginx_issue271_converter_default_buffering_second_body_progress_refresh_differential
        PROPERTIES
        LABELS "integration;nginx;docker;io_uring;network;differential"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 180
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue271_pinned_default_buffering_201_incomplete_body_inactivity_expiry_oracle
        COMMAND test_nginx_differential
                --pinned-nginx-default-buffering-201-incomplete-body-inactivity-expiry-oracle
    )
    set_tests_properties(
        test_nginx_issue271_pinned_default_buffering_201_incomplete_body_inactivity_expiry_oracle
        PROPERTIES
        LABELS "integration;nginx;docker;network;differential"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 120
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue271_pinned_default_buffering_202_incomplete_body_inactivity_expiry_oracle
        COMMAND test_nginx_differential
                --pinned-nginx-default-buffering-202-incomplete-body-inactivity-expiry-oracle
    )
    set_tests_properties(
        test_nginx_issue271_pinned_default_buffering_202_incomplete_body_inactivity_expiry_oracle
        PROPERTIES
        LABELS "integration;nginx;docker;network;differential"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 120
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue271_converter_default_buffering_201_incomplete_body_inactivity_expiry_differential
        COMMAND test_nginx_differential
                --converter-default-buffering-201-incomplete-body-inactivity-expiry-differential
                $<TARGET_FILE:rut>
    )
    set_tests_properties(
        test_nginx_issue271_converter_default_buffering_201_incomplete_body_inactivity_expiry_differential
        PROPERTIES
        LABELS "integration;nginx;docker;io_uring;network;differential"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 180
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue523_converter_default_buffering_202_incomplete_body_inactivity_expiry_differential
        COMMAND test_nginx_differential
                --converter-default-buffering-202-incomplete-body-inactivity-expiry-differential
                $<TARGET_FILE:rut>
    )
    set_tests_properties(
        test_nginx_issue523_converter_default_buffering_202_incomplete_body_inactivity_expiry_differential
        PROPERTIES
        LABELS "integration;nginx;docker;io_uring;network;differential"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 180
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue271_pinned_default_buffering_third_body_progress_expiry_oracle
        COMMAND test_nginx_differential
                --pinned-nginx-default-buffering-third-body-progress-expiry-oracle
    )
    set_tests_properties(
        test_nginx_issue271_pinned_default_buffering_third_body_progress_expiry_oracle PROPERTIES
        LABELS "integration;nginx;docker;network;differential"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 120
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue271_pinned_default_buffering_three_publication_completion_oracle
        COMMAND test_nginx_differential
                --pinned-nginx-default-buffering-three-publication-completion-oracle
    )
    set_tests_properties(
        test_nginx_issue271_pinned_default_buffering_three_publication_completion_oracle PROPERTIES
        LABELS "integration;nginx;docker;network;differential"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 120
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue271_converter_default_buffering_third_body_progress_expiry_differential
        COMMAND test_nginx_differential
                --converter-default-buffering-third-body-progress-expiry-differential
                $<TARGET_FILE:rut>
    )
    set_tests_properties(
        test_nginx_issue271_converter_default_buffering_third_body_progress_expiry_differential
        PROPERTIES
        LABELS "integration;nginx;docker;io_uring;network;differential"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 180
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue271_converter_default_buffering_three_publication_completion_differential
        COMMAND test_nginx_differential
                --converter-default-buffering-three-publication-completion-differential
                $<TARGET_FILE:rut>
    )
    set_tests_properties(
        test_nginx_issue271_converter_default_buffering_three_publication_completion_differential
        PROPERTIES
        LABELS "integration;nginx;docker;io_uring;network;differential"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 180
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue268_pinned_positive_cl_options_default_buffering_oracle
        COMMAND test_nginx_differential
                --pinned-nginx-positive-cl-options-default-buffering-oracle
    )
    set_tests_properties(
        test_nginx_issue268_pinned_positive_cl_options_default_buffering_oracle PROPERTIES
        LABELS "integration;nginx;docker;network"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 90
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue268_pinned_positive_cl_head_default_buffering_oracle
        COMMAND test_nginx_differential
                --pinned-nginx-positive-cl-head-default-buffering-oracle
    )
    set_tests_properties(
        test_nginx_issue268_pinned_positive_cl_head_default_buffering_oracle PROPERTIES
        LABELS "integration;nginx;docker;network"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 90
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue362_request_length_oracle
        COMMAND test_nginx_differential --pinned-nginx-request-length-oracle
    )
    set_tests_properties(test_nginx_issue362_request_length_oracle PROPERTIES
        LABELS "integration;nginx;docker;network"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 90
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue370_request_length_split_header_oracle
        COMMAND test_nginx_differential --pinned-nginx-request-length-split-header-oracle
    )
    set_tests_properties(test_nginx_issue370_request_length_split_header_oracle PROPERTIES
        LABELS "integration;nginx;docker;network"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 90
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue371_rut_initial_header_split_public
        COMMAND test_nginx_differential --rut-initial-header-split-public $<TARGET_FILE:rut>
    )
    set_tests_properties(test_nginx_issue371_rut_initial_header_split_public PROPERTIES
        LABELS "integration;network;io_uring"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 60
    )
    add_test(
        NAME test_nginx_issue367_request_length_fixed_body_oracle
        COMMAND test_nginx_differential --pinned-nginx-request-length-fixed-body-oracle
    )
    set_tests_properties(test_nginx_issue367_request_length_fixed_body_oracle PROPERTIES
        LABELS "integration;nginx;docker;network"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 90
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue369_request_length_split_fixed_body_oracle
        COMMAND test_nginx_differential --pinned-nginx-request-length-split-fixed-body-oracle
    )
    set_tests_properties(test_nginx_issue369_request_length_split_fixed_body_oracle PROPERTIES
        LABELS "integration;nginx;docker;network"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 90
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue362_converter_request_length_differential
        COMMAND test_nginx_differential --converter-request-length-differential $<TARGET_FILE:rut>
    )
    set_tests_properties(test_nginx_issue362_converter_request_length_differential PROPERTIES
        LABELS "integration;nginx;docker;io_uring;network"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 120
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue370_converter_request_length_split_header_differential
        COMMAND test_nginx_differential
                --converter-request-length-split-header-differential $<TARGET_FILE:rut>
    )
    set_tests_properties(
        test_nginx_issue370_converter_request_length_split_header_differential PROPERTIES
        LABELS "integration;nginx;docker;io_uring;network"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 120
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue367_converter_request_length_fixed_body_differential
        COMMAND test_nginx_differential --converter-request-length-fixed-body-differential
                $<TARGET_FILE:rut>
    )
    set_tests_properties(
        test_nginx_issue367_converter_request_length_fixed_body_differential PROPERTIES
        LABELS "integration;nginx;docker;io_uring;network"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 120
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue369_converter_request_length_split_fixed_body_differential
        COMMAND test_nginx_differential --converter-request-length-split-fixed-body-differential
                $<TARGET_FILE:rut>
    )
    set_tests_properties(
        test_nginx_issue369_converter_request_length_split_fixed_body_differential PROPERTIES
        LABELS "integration;nginx;docker;io_uring;network"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 120
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue342_wildcard_listen_oracle
        COMMAND test_nginx_differential --pinned-nginx-wildcard-listen-oracle
    )
    set_tests_properties(test_nginx_issue342_wildcard_listen_oracle PROPERTIES
        LABELS "integration;nginx;docker"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 90
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue343_asterisk_wildcard_listen_oracle
        COMMAND test_nginx_differential --pinned-nginx-asterisk-wildcard-listen-oracle
    )
    set_tests_properties(test_nginx_issue343_asterisk_wildcard_listen_oracle PROPERTIES
        LABELS "integration;nginx;docker"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 90
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue344_exact_loopback_listen_oracle
        COMMAND test_nginx_differential --pinned-nginx-exact-loopback-listen-oracle
    )
    set_tests_properties(test_nginx_issue344_exact_loopback_listen_oracle PROPERTIES
        LABELS "integration;nginx;docker;network"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 90
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue348_exact_loopback_return204_oracle
        COMMAND test_nginx_differential --pinned-nginx-exact-loopback-return204-oracle
    )
    set_tests_properties(test_nginx_issue348_exact_loopback_return204_oracle PROPERTIES
        LABELS "integration;nginx;docker;network"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 120
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue349_exact_loopback_bodyful_return_oracle
        COMMAND test_nginx_differential --pinned-nginx-exact-loopback-bodyful-return-oracle
    )
    set_tests_properties(test_nginx_issue349_exact_loopback_bodyful_return_oracle PROPERTIES
        LABELS "integration;nginx;docker;network"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 120
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue350_exact_loopback_return302_oracle
        COMMAND test_nginx_differential --pinned-nginx-exact-loopback-return302-oracle
    )
    set_tests_properties(test_nginx_issue350_exact_loopback_return302_oracle PROPERTIES
        LABELS "integration;nginx;docker;network"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 180
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue351_exact_loopback_return301_oracle
        COMMAND test_nginx_differential --pinned-nginx-exact-loopback-return301-oracle
    )
    set_tests_properties(test_nginx_issue351_exact_loopback_return301_oracle PROPERTIES
        LABELS "integration;nginx;docker;network"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 180
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue353_exact_loopback_prefix_root_replacement_oracle
        COMMAND test_nginx_differential
                --pinned-nginx-exact-loopback-prefix-root-replacement-oracle
    )
    set_tests_properties(
        test_nginx_issue353_exact_loopback_prefix_root_replacement_oracle PROPERTIES
        LABELS "integration;nginx;docker;network"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 180
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue354_exact_loopback_api_v1_replacement_oracle
        COMMAND test_nginx_differential
                --pinned-nginx-exact-loopback-api-v1-replacement-oracle
    )
    set_tests_properties(
        test_nginx_issue354_exact_loopback_api_v1_replacement_oracle PROPERTIES
        LABELS "integration;nginx;docker;network"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 180
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue355_exact_loopback_api_no_uri_oracle
        COMMAND test_nginx_differential
                --pinned-nginx-exact-loopback-api-no-uri-oracle
    )
    set_tests_properties(
        test_nginx_issue355_exact_loopback_api_no_uri_oracle PROPERTIES
        LABELS "integration;nginx;docker;network"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 180
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue356_exact_loopback_service_no_uri_oracle
        COMMAND test_nginx_differential
                --pinned-nginx-exact-loopback-service-no-uri-oracle
    )
    set_tests_properties(
        test_nginx_issue356_exact_loopback_service_no_uri_oracle PROPERTIES
        LABELS "integration;nginx;docker;network"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 180
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue342_converter_wildcard_listen_differential
        COMMAND test_nginx_differential --converter-wildcard-listen-differential
                $<TARGET_FILE:rut>
    )
    set_tests_properties(
        test_nginx_issue342_converter_wildcard_listen_differential PROPERTIES
        LABELS "integration;nginx;docker;io_uring;network"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 180
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue343_converter_asterisk_wildcard_listen_differential
        COMMAND test_nginx_differential --converter-asterisk-wildcard-listen-differential
                $<TARGET_FILE:rut>
    )
    set_tests_properties(
        test_nginx_issue343_converter_asterisk_wildcard_listen_differential PROPERTIES
        LABELS "integration;nginx;docker;io_uring;network"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 180
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue344_converter_exact_loopback_listen_differential
        COMMAND test_nginx_differential --converter-exact-loopback-listen-differential
                $<TARGET_FILE:rut>
    )
    set_tests_properties(
        test_nginx_issue344_converter_exact_loopback_listen_differential PROPERTIES
        LABELS "integration;nginx;docker;io_uring;network"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 180
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue348_converter_exact_loopback_return204_differential
        COMMAND test_nginx_differential --converter-exact-loopback-return204-differential
                $<TARGET_FILE:rut>
    )
    set_tests_properties(
        test_nginx_issue348_converter_exact_loopback_return204_differential PROPERTIES
        LABELS "integration;nginx;docker;io_uring;network"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 180
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue349_converter_exact_loopback_bodyful_return_differential
        COMMAND test_nginx_differential
                --converter-exact-loopback-bodyful-return-differential
                $<TARGET_FILE:rut>
    )
    set_tests_properties(
        test_nginx_issue349_converter_exact_loopback_bodyful_return_differential PROPERTIES
        LABELS "integration;nginx;docker;io_uring;network"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 180
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue350_converter_exact_loopback_return302_differential
        COMMAND test_nginx_differential
                --converter-exact-loopback-return302-differential
                $<TARGET_FILE:rut>
    )
    set_tests_properties(
        test_nginx_issue350_converter_exact_loopback_return302_differential PROPERTIES
        LABELS "integration;nginx;docker;io_uring;network"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 180
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue351_converter_exact_loopback_return301_differential
        COMMAND test_nginx_differential
                --converter-exact-loopback-return301-differential
                $<TARGET_FILE:rut>
    )
    set_tests_properties(
        test_nginx_issue351_converter_exact_loopback_return301_differential PROPERTIES
        LABELS "integration;nginx;docker;io_uring;network"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 180
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue353_converter_exact_loopback_prefix_root_replacement_differential
        COMMAND test_nginx_differential
                --converter-exact-loopback-prefix-root-replacement-differential
                $<TARGET_FILE:rut>
    )
    set_tests_properties(
        test_nginx_issue353_converter_exact_loopback_prefix_root_replacement_differential PROPERTIES
        LABELS "integration;nginx;docker;io_uring;network"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 180
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue354_converter_exact_loopback_api_v1_replacement_differential
        COMMAND test_nginx_differential
                --converter-exact-loopback-api-v1-replacement-differential
                $<TARGET_FILE:rut>
    )
    set_tests_properties(
        test_nginx_issue354_converter_exact_loopback_api_v1_replacement_differential PROPERTIES
        LABELS "integration;nginx;docker;io_uring;network"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 180
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue355_converter_exact_loopback_api_no_uri_differential
        COMMAND test_nginx_differential
                --converter-exact-loopback-api-no-uri-differential
                $<TARGET_FILE:rut>
    )
    set_tests_properties(
        test_nginx_issue355_converter_exact_loopback_api_no_uri_differential PROPERTIES
        LABELS "integration;nginx;docker;io_uring;network"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 180
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue356_converter_exact_loopback_service_no_uri_differential
        COMMAND test_nginx_differential
                --converter-exact-loopback-service-no-uri-differential
                $<TARGET_FILE:rut>
    )
    set_tests_properties(
        test_nginx_issue356_converter_exact_loopback_service_no_uri_differential PROPERTIES
        LABELS "integration;nginx;docker;io_uring;network"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 180
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue357_converter_wildcard_service_no_uri_differential
        COMMAND test_nginx_differential
                --converter-wildcard-service-no-uri-differential
                $<TARGET_FILE:rut>
    )
    set_tests_properties(
        test_nginx_issue357_converter_wildcard_service_no_uri_differential PROPERTIES
        LABELS "integration;nginx;docker;io_uring;network"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 180
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue353_converter_exact_loopback_max_proxy_prefix_differential
        COMMAND test_nginx_differential
                --converter-exact-loopback-max-proxy-prefix-differential
                $<TARGET_FILE:rut>
    )
    set_tests_properties(
        test_nginx_issue353_converter_exact_loopback_max_proxy_prefix_differential PROPERTIES
        LABELS "integration;nginx;docker;io_uring;network"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 180
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue356_converter_exact_loopback_max_no_uri_prefix_differential
        COMMAND test_nginx_differential
                --converter-exact-loopback-max-no-uri-prefix-differential
                $<TARGET_FILE:rut>
    )
    set_tests_properties(
        test_nginx_issue356_converter_exact_loopback_max_no_uri_prefix_differential PROPERTIES
        LABELS "integration;nginx;docker;io_uring;network"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 180
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue357_converter_wildcard_max_no_uri_prefix_differential
        COMMAND test_nginx_differential
                --converter-wildcard-max-no-uri-prefix-differential
                $<TARGET_FILE:rut>
    )
    set_tests_properties(
        test_nginx_issue357_converter_wildcard_max_no_uri_prefix_differential PROPERTIES
        LABELS "integration;nginx;docker;io_uring;network"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 180
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_converter_static_query_proxy_uri_differential
        COMMAND test_nginx_differential --converter-static-query-proxy-uri-differential
                $<TARGET_FILE:rut>
    )
    set_tests_properties(test_nginx_converter_static_query_proxy_uri_differential PROPERTIES
        LABELS "integration;nginx;docker;io_uring;network"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 180
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue341_converter_zero_suffix_static_query_proxy_uri_differential
        COMMAND test_nginx_differential
                --converter-zero-suffix-static-query-proxy-uri-differential
                $<TARGET_FILE:rut>
    )
    set_tests_properties(
        test_nginx_issue341_converter_zero_suffix_static_query_proxy_uri_differential PROPERTIES
        LABELS "integration;nginx;docker;io_uring;network"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 180
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue360_converter_empty_query_proxy_uri_differential
        COMMAND test_nginx_differential
                --converter-empty-query-proxy-uri-differential
                $<TARGET_FILE:rut>
    )
    set_tests_properties(
        test_nginx_issue360_converter_empty_query_proxy_uri_differential PROPERTIES
        LABELS "integration;nginx;docker;io_uring;network"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 240
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_issue372_converter_root_empty_query_proxy_uri_differential
        COMMAND test_nginx_differential
                --converter-root-empty-query-proxy-uri-differential
                $<TARGET_FILE:rut>
    )
    set_tests_properties(
        test_nginx_issue372_converter_root_empty_query_proxy_uri_differential PROPERTIES
        LABELS "integration;nginx;docker;io_uring;network"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 240
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_bounded_exact_local_path_oracle
        COMMAND test_nginx_differential --bounded-exact-local-path-oracle
    )
    set_tests_properties(test_nginx_bounded_exact_local_path_oracle PROPERTIES
        LABELS "integration;nginx;docker"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 60
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_bounded_no_content_path_oracle
        COMMAND test_nginx_differential --bounded-no-content-path-oracle
    )
    set_tests_properties(test_nginx_bounded_no_content_path_oracle PROPERTIES
        LABELS "integration;nginx;docker"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 90
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_normalized_exact_trailing_slash_oracle
        COMMAND test_nginx_differential --normalized-exact-trailing-slash-oracle
    )
    set_tests_properties(test_nginx_normalized_exact_trailing_slash_oracle PROPERTIES
        LABELS "integration;nginx;docker"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 75
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_trailing_slash_no_content_oracle
        COMMAND test_nginx_differential --trailing-slash-no-content-oracle
    )
    set_tests_properties(test_nginx_trailing_slash_no_content_oracle PROPERTIES
        LABELS "integration;nginx;docker"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 90
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_max_boundary_no_content_oracle
        COMMAND test_nginx_differential --max-boundary-no-content-oracle
    )
    set_tests_properties(test_nginx_max_boundary_no_content_oracle PROPERTIES
        LABELS "integration;nginx;docker"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 120
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_bodyful_normalized_exact_oracle
        COMMAND test_nginx_differential --bodyful-normalized-exact-oracle
    )
    set_tests_properties(test_nginx_bodyful_normalized_exact_oracle PROPERTIES
        LABELS "integration;nginx;docker"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 120
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_exact_local_body_space_oracle
        COMMAND test_nginx_differential --exact-local-body-space-oracle
    )
    set_tests_properties(test_nginx_exact_local_body_space_oracle PROPERTIES
        LABELS "integration;nginx;docker"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 75
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_exact_local_body_multiple_space_oracle
        COMMAND test_nginx_differential --exact-local-body-multiple-space-oracle
    )
    set_tests_properties(test_nginx_exact_local_body_multiple_space_oracle PROPERTIES
        LABELS "integration;nginx;docker"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 120
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_converter_exact_local_body_space_differential
        COMMAND test_nginx_differential --converter-exact-local-body-space-differential
                $<TARGET_FILE:rut>
    )
    set_tests_properties(test_nginx_converter_exact_local_body_space_differential PROPERTIES
        LABELS "integration;nginx;docker"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 120
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_converter_exact_local_body_multiple_space_differential
        COMMAND test_nginx_differential
                --converter-exact-local-body-multiple-space-differential
                $<TARGET_FILE:rut>
    )
    set_tests_properties(test_nginx_converter_exact_local_body_multiple_space_differential
        PROPERTIES
        LABELS "integration;nginx;docker"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 180
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_converter_exact_local_return204_differential
        COMMAND test_nginx_differential --converter-exact-local-return204-differential
                $<TARGET_FILE:rut>
    )
    set_tests_properties(test_nginx_converter_exact_local_return204_differential PROPERTIES
        LABELS "integration;nginx;docker;network;io_uring"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 150
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_converter_exact_local_return204_query_differential
        COMMAND test_nginx_differential --converter-exact-local-return204-query-differential
                $<TARGET_FILE:rut>
    )
    set_tests_properties(test_nginx_converter_exact_local_return204_query_differential PROPERTIES
        LABELS "integration;nginx;docker;network;io_uring"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 150
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_converter_bounded_exact_local_path_differential
        COMMAND test_nginx_differential --converter-bounded-exact-local-path-differential
                $<TARGET_FILE:rut>
    )
    set_tests_properties(test_nginx_converter_bounded_exact_local_path_differential PROPERTIES
        LABELS "integration;nginx;docker"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 90
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_converter_bounded_no_content_path_differential
        COMMAND test_nginx_differential --converter-bounded-no-content-path-differential
                $<TARGET_FILE:rut>
    )
    set_tests_properties(test_nginx_converter_bounded_no_content_path_differential PROPERTIES
        LABELS "integration;nginx;docker;network;io_uring"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 180
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_converter_trailing_slash_no_content_differential
        COMMAND test_nginx_differential --converter-trailing-slash-no-content-differential
                $<TARGET_FILE:rut>
    )
    set_tests_properties(test_nginx_converter_trailing_slash_no_content_differential PROPERTIES
        LABELS "integration;nginx;docker;network;io_uring"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 180
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_converter_max_boundary_no_content_differential
        COMMAND test_nginx_differential --converter-max-boundary-no-content-differential
                $<TARGET_FILE:rut>
    )
    set_tests_properties(test_nginx_converter_max_boundary_no_content_differential PROPERTIES
        LABELS "integration;nginx;docker;network;io_uring"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 180
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_converter_bodyful_normalized_exact_differential
        COMMAND test_nginx_differential --converter-bodyful-normalized-exact-differential
                $<TARGET_FILE:rut>
    )
    set_tests_properties(test_nginx_converter_bodyful_normalized_exact_differential PROPERTIES
        LABELS "integration;nginx;docker;network;io_uring"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 180
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_converter_normalized_exact_trailing_slash_differential
        COMMAND test_nginx_differential
                --converter-normalized-exact-trailing-slash-differential
                $<TARGET_FILE:rut>
    )
    set_tests_properties(test_nginx_converter_normalized_exact_trailing_slash_differential
        PROPERTIES
        LABELS "integration;nginx;docker"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 150
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_converter_api_non_root_proxy_uri_differential
        COMMAND test_nginx_differential --converter-api-non-root-proxy-uri-differential
                $<TARGET_FILE:rut>
    )
    set_tests_properties(test_nginx_converter_api_non_root_proxy_uri_differential PROPERTIES
        LABELS "integration;nginx;docker"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 90
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_converter_service_root_proxy_uri_differential
        COMMAND test_nginx_differential --converter-service-root-proxy-uri-differential
                $<TARGET_FILE:rut>
    )
    set_tests_properties(test_nginx_converter_service_root_proxy_uri_differential PROPERTIES
        LABELS "integration;nginx;docker"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 90
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_converter_max_proxy_prefix_differential
        COMMAND test_nginx_differential --converter-max-proxy-prefix-differential
                $<TARGET_FILE:rut>
    )
    set_tests_properties(test_nginx_converter_max_proxy_prefix_differential PROPERTIES
        LABELS "integration;nginx;docker;io_uring;network"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 120
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_converter_max_proxy_replacement_differential
        COMMAND test_nginx_differential --converter-max-proxy-replacement-differential
                $<TARGET_FILE:rut>
    )
    set_tests_properties(test_nginx_converter_max_proxy_replacement_differential PROPERTIES
        LABELS "integration;nginx;docker;io_uring;network"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 120
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_converter_exact_absolute_redirect_differential
        COMMAND test_nginx_differential --converter-exact-absolute-redirect-differential
                $<TARGET_FILE:rut>
    )
    set_tests_properties(test_nginx_converter_exact_absolute_redirect_differential PROPERTIES
        LABELS "integration;nginx;docker"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 60
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_converter_exact_absolute_redirect_302_differential
        COMMAND test_nginx_differential --converter-exact-absolute-redirect-302-differential
                $<TARGET_FILE:rut>
    )
    set_tests_properties(test_nginx_converter_exact_absolute_redirect_302_differential PROPERTIES
        LABELS "integration;nginx;docker"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 60
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_converter_root_proxy_trace_differential
        COMMAND test_nginx_differential --converter-root-proxy-trace-differential
                $<TARGET_FILE:rut>
    )
    set_tests_properties(test_nginx_converter_root_proxy_trace_differential PROPERTIES
        LABELS "integration;nginx;docker"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 60
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_converter_api_proxy_trace_differential
        COMMAND test_nginx_differential --converter-api-proxy-trace-differential
                $<TARGET_FILE:rut>
    )
    set_tests_properties(test_nginx_converter_api_proxy_trace_differential PROPERTIES
        LABELS "integration;nginx;docker"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 60
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_strict_local_response_differential
        COMMAND test_nginx_differential --strict-local-response-differential
                $<TARGET_FILE:rut>
    )
    set_tests_properties(test_nginx_strict_local_response_differential PROPERTIES
        LABELS "integration;nginx;docker"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 60
        SKIP_RETURN_CODE 77
    )
    add_test(
        NAME test_nginx_converter_exact_local_differential
        COMMAND test_nginx_differential --converter-exact-local-differential
                $<TARGET_FILE:rut>
    )
    set_tests_properties(test_nginx_converter_exact_local_differential PROPERTIES
        LABELS "integration;nginx;docker"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 60
        SKIP_RETURN_CODE 77
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_nginx_exact_strict_route_differential
        COMMAND test_nginx_differential --exact-strict-route-differential
                $<TARGET_FILE:rut>
    )
    set_tests_properties(test_nginx_exact_strict_route_differential PROPERTIES
        LABELS "integration;nginx;docker"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 60
        SKIP_RETURN_CODE 77
    )
    add_test(
        NAME test_rut_slash_normalized_exact_production
        COMMAND test_nginx_differential --slash-normalized-exact-rut-production
                $<TARGET_FILE:rut>
    )
    set_tests_properties(test_rut_slash_normalized_exact_production PROPERTIES
        LABELS "integration;network;io_uring"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 60
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_rut_no_content204_production
        COMMAND test_nginx_differential --no-content204-rut-production
                $<TARGET_FILE:rut>
    )
    set_tests_properties(test_rut_no_content204_production PROPERTIES
        LABELS "integration;network;io_uring"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 60
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    add_test(
        NAME test_rut_exact_ipv4_listener_production
        COMMAND test_nginx_differential --rut-exact-ipv4-listener-production
                $<TARGET_FILE:rut>
    )
    set_tests_properties(test_rut_exact_ipv4_listener_production PROPERTIES
        LABELS "integration;network;io_uring"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 60
        ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
    )
    if(TARGET test_rut_iouring_gate_preload)
        add_test(
            NAME test_rut_iouring_gate_spike
            COMMAND test_nginx_differential --rut-iouring-gate-spike
                    $<TARGET_FILE:rut> $<TARGET_FILE:test_rut_iouring_gate_preload>
        )
        set_tests_properties(test_rut_iouring_gate_spike PROPERTIES
            LABELS "integration;nginx"
            RUN_SERIAL TRUE
            RESOURCE_LOCK nginx-differential
            TIMEOUT 30
        )
        add_test(
            NAME test_rut_iouring_gate_identity_negative
            COMMAND test_nginx_differential --rut-iouring-gate-identity-negative
                    $<TARGET_FILE:rut> $<TARGET_FILE:test_rut_iouring_gate_preload>
        )
        set_tests_properties(test_rut_iouring_gate_identity_negative PROPERTIES
            LABELS "integration;nginx;negative"
            RUN_SERIAL TRUE
            RESOURCE_LOCK nginx-differential
            TIMEOUT 30
        )
        add_test(
            NAME test_rut_iouring_gate_ready_mutation_negative
            COMMAND test_nginx_differential --rut-iouring-gate-ready-mutation-negative
                    $<TARGET_FILE:rut> $<TARGET_FILE:test_rut_iouring_gate_preload>
        )
        set_tests_properties(test_rut_iouring_gate_ready_mutation_negative PROPERTIES
            LABELS "integration;nginx;negative"
            RUN_SERIAL TRUE
            RESOURCE_LOCK nginx-differential
            TIMEOUT 30
        )
        add_test(
            NAME test_rut_iouring_gate_owner_death_negative
            COMMAND test_nginx_differential --rut-iouring-gate-owner-death-negative
                    $<TARGET_FILE:rut> $<TARGET_FILE:test_rut_iouring_gate_preload>
        )
        set_tests_properties(test_rut_iouring_gate_owner_death_negative PROPERTIES
            LABELS "integration;nginx;negative"
            RUN_SERIAL TRUE
            RESOURCE_LOCK nginx-differential
            TIMEOUT 30
        )
        add_test(
            NAME test_rut_iouring_gate_connect_journal_negative
            COMMAND test_nginx_differential --rut-iouring-gate-connect-journal-negative
                    $<TARGET_FILE:rut> $<TARGET_FILE:test_rut_iouring_gate_preload>
        )
        set_tests_properties(test_rut_iouring_gate_connect_journal_negative PROPERTIES
            LABELS "integration;nginx;negative"
            RUN_SERIAL TRUE
            RESOURCE_LOCK nginx-differential
            TIMEOUT 30
        )
        add_test(
            NAME test_rut_iouring_coalesced_ingress_gate
            COMMAND test_nginx_differential --rut-iouring-coalesced-ingress-gate
                    $<TARGET_FILE:rut> $<TARGET_FILE:test_rut_iouring_gate_preload>
        )
        set_tests_properties(test_rut_iouring_coalesced_ingress_gate PROPERTIES
            LABELS "integration;nginx"
            RUN_SERIAL TRUE
            RESOURCE_LOCK nginx-differential
            TIMEOUT 30
            ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
        )
        add_test(
            NAME test_nginx_converter_coalesced_successor_differential
            COMMAND test_nginx_differential --converter-coalesced-successor-differential
                    $<TARGET_FILE:rut>
                    $<TARGET_FILE:test_nginx_downstream_gate_preload>
                    $<TARGET_FILE:test_rut_iouring_gate_preload>
        )
        set_tests_properties(test_nginx_converter_coalesced_successor_differential PROPERTIES
            LABELS "integration;nginx;docker"
            RUN_SERIAL TRUE
            RESOURCE_LOCK nginx-differential
            TIMEOUT 90
            SKIP_RETURN_CODE 77
            ENVIRONMENT "RUT_NGINX_DIFFERENTIAL_REQUIRED=1"
        )
        add_test(
            NAME test_nginx_late_successor_differential
            COMMAND test_nginx_differential --late-successor-differential
                    $<TARGET_FILE:rut>
                    $<TARGET_FILE:test_nginx_downstream_gate_preload>
                    $<TARGET_FILE:test_rut_iouring_gate_preload>
        )
        set_tests_properties(test_nginx_late_successor_differential PROPERTIES
            LABELS "integration;nginx;docker"
            RUN_SERIAL TRUE
            RESOURCE_LOCK nginx-differential
            TIMEOUT 60
            SKIP_RETURN_CODE 77
        )
    endif()
    if(TARGET test_rut_iouring_gate_preload)
        add_test(
            NAME test_nginx_differential
            COMMAND test_nginx_differential $<TARGET_FILE:rut>
                    $<TARGET_FILE:test_nginx_downstream_gate_preload>
                    $<TARGET_FILE:test_rut_iouring_gate_preload>
        )
    else()
        add_test(
            NAME test_nginx_differential
            COMMAND test_nginx_differential $<TARGET_FILE:rut>
        )
    endif()
    set_tests_properties(test_nginx_differential PROPERTIES
        LABELS "integration;nginx;docker"
        RUN_SERIAL TRUE
        RESOURCE_LOCK nginx-differential
        TIMEOUT 120
        SKIP_RETURN_CODE 77
    )

    add_executable(test_jit test_jit.cc ${PROJECT_SOURCE_DIR}/src/placement_new.cc)
    target_link_libraries(test_jit rut_jit rut_compiler)
    target_include_directories(test_jit PRIVATE
        ${PROJECT_SOURCE_DIR}/include
        ${PROJECT_SOURCE_DIR}/testing
        ${LLVM_INCLUDE_DIRS}
    )
    target_compile_definitions(test_jit PRIVATE ${LLVM_DEFINITIONS})
    add_test(NAME test_jit COMMAND test_jit)
    set_tests_properties(test_jit PROPERTIES LABELS "unit;jit")

    # Exercise the same reusable loader library linked by rut and SourceTarget.
    add_executable(test_serve_loader test_serve_loader.cc)
    target_link_libraries(test_serve_loader rut_loader rut_nginx)
    target_include_directories(test_serve_loader PRIVATE
        ${PROJECT_SOURCE_DIR}/include
        ${PROJECT_SOURCE_DIR}/testing
        ${LLVM_INCLUDE_DIRS}
    )
    target_compile_definitions(test_serve_loader PRIVATE ${LLVM_DEFINITIONS} RUT_ENABLE_JIT=1)
    add_test(NAME test_serve_loader COMMAND test_serve_loader)
    set_tests_properties(test_serve_loader PROPERTIES LABELS "unit;jit")
endif()

add_executable(test_traffic_capture
    test_traffic_capture.cc
    ${PROJECT_SOURCE_DIR}/testing/fault_injection.cc
)
target_link_libraries(test_traffic_capture rut_runtime Threads::Threads)
target_include_directories(test_traffic_capture PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/testing
    ${CMAKE_CURRENT_SOURCE_DIR}
)
add_test(NAME test_traffic_capture COMMAND test_traffic_capture)
set_tests_properties(test_traffic_capture PROPERTIES LABELS "unit")

add_executable(test_traffic_replay
    test_traffic_replay.cc
    ${PROJECT_SOURCE_DIR}/testing/fault_injection.cc
)
target_link_libraries(test_traffic_replay rut_runtime rut_harness_core)
target_include_directories(test_traffic_replay PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/testing
    ${CMAKE_CURRENT_SOURCE_DIR}
)
add_test(NAME test_traffic_replay COMMAND test_traffic_replay)
set_tests_properties(test_traffic_replay PROPERTIES LABELS "unit")

add_executable(test_sim test_sim.cc)
target_link_libraries(test_sim rut_runtime Threads::Threads)
target_include_directories(test_sim PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/testing
    ${CMAKE_CURRENT_SOURCE_DIR}
)
add_test(NAME test_sim COMMAND test_sim)
set_tests_properties(test_sim PROPERTIES LABELS "integration;sim")

add_executable(test_harness test_harness.cc)
target_link_libraries(test_harness rut_harness_core)
target_include_directories(test_harness PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/testing
    ${CMAKE_CURRENT_SOURCE_DIR}
)
add_test(NAME test_harness COMMAND test_harness)
set_tests_properties(test_harness PROPERTIES LABELS "unit;harness")

if(RUT_ENABLE_JIT)
    target_sources(test_harness PRIVATE ${PROJECT_SOURCE_DIR}/testing/fault_injection.cc)
    target_link_libraries(test_harness rut_harness_runtime)
    target_include_directories(test_harness PRIVATE ${LLVM_INCLUDE_DIRS})
    target_compile_definitions(test_harness PRIVATE
        RUT_ENABLE_JIT_TESTS=1
        ${LLVM_DEFINITIONS}
    )
else()
    target_compile_definitions(test_harness PRIVATE RUT_ENABLE_JIT_TESTS=0)
endif()

if(RUT_ENABLE_JIT)
    add_executable(test_simulate_engine test_simulate_engine.cc)
    add_dependencies(test_simulate_engine rut-simulate)
    target_link_libraries(test_simulate_engine rut_simulate)
    target_include_directories(test_simulate_engine PRIVATE
        ${PROJECT_SOURCE_DIR}/include
        ${PROJECT_SOURCE_DIR}/testing
        ${LLVM_INCLUDE_DIRS}
    )
    target_compile_definitions(test_simulate_engine PRIVATE ${LLVM_DEFINITIONS})
    target_compile_definitions(test_simulate_engine PRIVATE
        RUT_SIMULATE_BIN_PATH="$<TARGET_FILE:rut-simulate>"
    )
    add_test(NAME test_simulate_engine COMMAND test_simulate_engine)
    set_tests_properties(test_simulate_engine PROPERTIES LABELS "unit;sim;jit")
endif()

add_test(
    NAME test_runtime_state_model
    COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/scripts/check_runtime_state_model.py
)
set_tests_properties(test_runtime_state_model PROPERTIES LABELS "unit;model")

if(RUT_ENABLE_JIT)
    add_custom_target(check
        COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/scripts/check_runtime_state_model.py
        COMMAND $<TARGET_FILE:test_network>
        COMMAND $<TARGET_FILE:test_integration>
        COMMAND $<TARGET_FILE:test_arena>
        COMMAND $<TARGET_FILE:test_expected>
        COMMAND $<TARGET_FILE:test_http_parser>
        COMMAND $<TARGET_FILE:test_http2>
        COMMAND $<TARGET_FILE:test_hpack>
        COMMAND $<TARGET_FILE:test_hpack_diff>
        COMMAND $<TARGET_FILE:test_http2_conn>
        COMMAND $<TARGET_FILE:test_buffer>
        COMMAND $<TARGET_FILE:test_cache_table>
        COMMAND $<TARGET_FILE:test_types>
        COMMAND $<TARGET_FILE:test_rir>
        COMMAND $<TARGET_FILE:test_frontend>
        COMMAND $<TARGET_FILE:test_nginx_parser>
        COMMAND $<TARGET_FILE:test_drain>
        COMMAND $<TARGET_FILE:test_access_log>
        COMMAND $<TARGET_FILE:test_metrics>
        COMMAND $<TARGET_FILE:test_debug>
        COMMAND $<TARGET_FILE:test_fault_injection>
        COMMAND $<TARGET_FILE:test_chunked_parser>
        COMMAND $<TARGET_FILE:test_shard_control>
        COMMAND $<TARGET_FILE:test_jit>
        COMMAND $<TARGET_FILE:test_serve_loader>
        COMMAND $<TARGET_FILE:test_traffic_capture>
        COMMAND $<TARGET_FILE:test_traffic_replay>
        COMMAND $<TARGET_FILE:test_sim>
        COMMAND $<TARGET_FILE:test_simulate_engine>
        COMMAND $<TARGET_FILE:test_harness>
        COMMAND $<TARGET_FILE:test_route_trie>
        COMMAND $<TARGET_FILE:test_route_art>
        COMMAND $<TARGET_FILE:test_route_select>
        COMMAND $<TARGET_FILE:test_target_transform>
        COMMAND $<TARGET_FILE:test_redirect_policy>
        DEPENDS test_network test_integration test_arena test_expected test_http_parser test_http2 test_hpack test_hpack_diff test_http2_conn test_chunked_parser test_buffer test_cache_table test_types test_rir test_frontend test_nginx_parser test_drain test_access_log test_metrics test_debug test_fault_injection test_shard_control test_jit test_serve_loader test_traffic_capture test_traffic_replay test_sim rut-simulate test_simulate_engine test_harness test_route_trie test_route_art test_route_select test_target_transform test_redirect_policy
        COMMENT "Running all tests..."
    )
else()
    add_custom_target(check
        COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/scripts/check_runtime_state_model.py
        COMMAND $<TARGET_FILE:test_network>
        COMMAND $<TARGET_FILE:test_integration>
        COMMAND $<TARGET_FILE:test_arena>
        COMMAND $<TARGET_FILE:test_expected>
        COMMAND $<TARGET_FILE:test_http_parser>
        COMMAND $<TARGET_FILE:test_http2>
        COMMAND $<TARGET_FILE:test_hpack>
        COMMAND $<TARGET_FILE:test_hpack_diff>
        COMMAND $<TARGET_FILE:test_http2_conn>
        COMMAND $<TARGET_FILE:test_buffer>
        COMMAND $<TARGET_FILE:test_cache_table>
        COMMAND $<TARGET_FILE:test_types>
        COMMAND $<TARGET_FILE:test_rir>
        COMMAND $<TARGET_FILE:test_frontend>
        COMMAND $<TARGET_FILE:test_nginx_parser>
        COMMAND $<TARGET_FILE:test_drain>
        COMMAND $<TARGET_FILE:test_access_log>
        COMMAND $<TARGET_FILE:test_metrics>
        COMMAND $<TARGET_FILE:test_debug>
        COMMAND $<TARGET_FILE:test_fault_injection>
        COMMAND $<TARGET_FILE:test_chunked_parser>
        COMMAND $<TARGET_FILE:test_shard_control>
        COMMAND $<TARGET_FILE:test_traffic_capture>
        COMMAND $<TARGET_FILE:test_traffic_replay>
        COMMAND $<TARGET_FILE:test_sim>
        COMMAND $<TARGET_FILE:test_harness>
        COMMAND $<TARGET_FILE:test_route_trie>
        COMMAND $<TARGET_FILE:test_route_art>
        COMMAND $<TARGET_FILE:test_route_select>
        COMMAND $<TARGET_FILE:test_target_transform>
        COMMAND $<TARGET_FILE:test_redirect_policy>
        DEPENDS test_network test_integration test_arena test_expected test_http_parser test_http2 test_hpack test_hpack_diff test_http2_conn test_chunked_parser test_buffer test_cache_table test_types test_rir test_frontend test_nginx_parser test_drain test_access_log test_metrics test_debug test_fault_injection test_shard_control test_traffic_capture test_traffic_replay test_sim test_harness test_route_trie test_route_art test_route_select test_target_transform test_redirect_policy
        COMMENT "Running non-JIT tests..."
    )
endif()
