add_executable(test_framework test_framework.cc)
target_include_directories(test_framework PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/testing
)
add_test(NAME test_framework COMMAND test_framework)
set_tests_properties(test_framework PROPERTIES WILL_FAIL TRUE)

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

find_package(Threads REQUIRED)
find_package(Python3 REQUIRED COMPONENTS Interpreter)

add_test(
    NAME test_design_validation_contract
    COMMAND ${Python3_EXECUTABLE}
            ${PROJECT_SOURCE_DIR}/examples/design-validation/audit.py
            --manifest ${PROJECT_SOURCE_DIR}/examples/design-validation/capabilities.json
            --root ${PROJECT_SOURCE_DIR}
)
set_tests_properties(
    test_design_validation_contract
    PROPERTIES LABELS "unit;conformance"
)
add_test(
    NAME test_design_validation_contract_self_test
    COMMAND ${Python3_EXECUTABLE}
            ${PROJECT_SOURCE_DIR}/examples/design-validation/test_audit.py
)
set_tests_properties(
    test_design_validation_contract_self_test
    PROPERTIES LABELS "unit;conformance"
)
add_test(
    NAME test_design_validation_sensitivity_self_test
    COMMAND ${Python3_EXECUTABLE}
            ${PROJECT_SOURCE_DIR}/examples/design-validation/test_sensitivity.py
)
set_tests_properties(
    test_design_validation_sensitivity_self_test
    PROPERTIES LABELS "unit;conformance;mutation"
)

set(RUT_TLS_TESTDATA_DIR ${CMAKE_CURRENT_BINARY_DIR}/testdata)
set(RUT_TLS_TEST_CERT ${RUT_TLS_TESTDATA_DIR}/localhost_cert.pem)
set(RUT_TLS_TEST_KEY ${RUT_TLS_TESTDATA_DIR}/localhost_key.pem)
set(RUT_TLS_TEST_SNI_CERT ${RUT_TLS_TESTDATA_DIR}/api_example_cert.pem)

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
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/api_example_cert.pem
    ${RUT_TLS_TEST_SNI_CERT}
    COPYONLY
)

add_custom_target(
    test_tls_fixtures
    DEPENDS ${RUT_TLS_TEST_CERT} ${RUT_TLS_TEST_KEY} ${RUT_TLS_TEST_SNI_CERT}
)

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
    target_link_libraries(test_integration rut_jit)
    target_compile_definitions(test_integration PRIVATE RUT_ENABLE_JIT_TESTS=1)
else()
    target_compile_definitions(test_integration PRIVATE RUT_ENABLE_JIT_TESTS=0)
endif()
add_dependencies(test_integration test_tls_fixtures)
add_test(NAME test_integration COMMAND test_integration)
set_tests_properties(test_integration PROPERTIES LABELS "integration;network")

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

add_executable(test_hash_table test_hash_table.cc)
target_include_directories(test_hash_table PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/testing
)
add_test(NAME test_hash_table COMMAND test_hash_table)
set_tests_properties(test_hash_table PROPERTIES LABELS "unit")

add_executable(test_control_plane_mutation test_control_plane_mutation.cc)
target_link_libraries(test_control_plane_mutation rut_runtime Threads::Threads)
target_include_directories(test_control_plane_mutation PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/testing
)
add_test(NAME test_control_plane_mutation COMMAND test_control_plane_mutation)
set_tests_properties(test_control_plane_mutation PROPERTIES LABELS "unit;runtime;harness")

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
target_link_libraries(test_frontend rut_compiler)
target_include_directories(test_frontend PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/testing
)
target_compile_definitions(test_frontend PRIVATE
    RUT_SOURCE_DIR="${PROJECT_SOURCE_DIR}"
)
add_test(NAME test_frontend COMMAND test_frontend)
set_tests_properties(test_frontend PROPERTIES LABELS "unit;compiler")

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
target_link_libraries(test_access_log rut_runtime)
target_include_directories(test_access_log PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/testing
    ${CMAKE_CURRENT_SOURCE_DIR}
)
add_test(NAME test_access_log COMMAND test_access_log)
set_tests_properties(test_access_log PROPERTIES LABELS "unit")

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
    target_link_libraries(test_serve_loader rut_loader)
    target_include_directories(test_serve_loader PRIVATE
        ${PROJECT_SOURCE_DIR}/include
        ${PROJECT_SOURCE_DIR}/testing
        ${LLVM_INCLUDE_DIRS}
    )
    target_compile_definitions(test_serve_loader PRIVATE ${LLVM_DEFINITIONS} RUT_ENABLE_JIT=1)
    add_test(NAME test_serve_loader COMMAND test_serve_loader)
    set_tests_properties(test_serve_loader PROPERTIES LABELS "unit;jit")

    add_executable(test_reload_coordinator test_reload_coordinator.cc)
    target_link_libraries(test_reload_coordinator rut_loader)
    target_include_directories(test_reload_coordinator PRIVATE
        ${PROJECT_SOURCE_DIR}/include
        ${PROJECT_SOURCE_DIR}/testing
        ${LLVM_INCLUDE_DIRS}
    )
    target_compile_definitions(test_reload_coordinator PRIVATE ${LLVM_DEFINITIONS} RUT_ENABLE_JIT=1)
    add_test(NAME test_reload_coordinator COMMAND test_reload_coordinator)
    set_tests_properties(test_reload_coordinator PROPERTIES LABELS "unit;jit;runtime;harness")

    add_test(
        NAME test_process_reload
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/test_process_reload.py
                --rut $<TARGET_FILE:rut>
    )
    set_tests_properties(test_process_reload PROPERTIES LABELS "integration;process;jit;harness")

    add_test(
        NAME test_backend_selection
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/test_backend_selection.py
                --rut $<TARGET_FILE:rut>
    )
    set_tests_properties(test_backend_selection PROPERTIES LABELS "integration;process;jit;network")

    add_test(
        NAME test_design_validation
        COMMAND ${PROJECT_SOURCE_DIR}/examples/design-validation/validate.sh $<TARGET_FILE:rut>
    )
    if(RUT_ENABLE_WEBSOCKET)
        set(_RUT_VALIDATION_WEBSOCKET 1)
    else()
        set(_RUT_VALIDATION_WEBSOCKET 0)
    endif()
    set_tests_properties(
        test_design_validation
        PROPERTIES
            ENVIRONMENT
                "RUT_VALIDATION_WEBSOCKET=${_RUT_VALIDATION_WEBSOCKET};RUT_VALIDATION_PROCESS_TESTS=0"
            LABELS "integration;process;jit;network;conformance"
            RUN_SERIAL TRUE
            TIMEOUT 120
    )

    add_test(
        NAME test_design_validation_sensitivity
        COMMAND ${Python3_EXECUTABLE}
                ${PROJECT_SOURCE_DIR}/examples/design-validation/sensitivity.py
                --rut $<TARGET_FILE:rut>
                --root ${PROJECT_SOURCE_DIR}
                --websocket ${_RUT_VALIDATION_WEBSOCKET}
    )
    set_tests_properties(
        test_design_validation_sensitivity
        PROPERTIES
            LABELS "integration;process;jit;network;conformance;mutation"
            RUN_SERIAL TRUE
            TIMEOUT 120
    )
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
        COMMAND $<TARGET_FILE:test_hash_table>
        COMMAND $<TARGET_FILE:test_types>
        COMMAND $<TARGET_FILE:test_rir>
        COMMAND $<TARGET_FILE:test_frontend>
        COMMAND $<TARGET_FILE:test_drain>
        COMMAND $<TARGET_FILE:test_access_log>
        COMMAND $<TARGET_FILE:test_metrics>
        COMMAND $<TARGET_FILE:test_debug>
        COMMAND $<TARGET_FILE:test_fault_injection>
        COMMAND $<TARGET_FILE:test_chunked_parser>
        COMMAND $<TARGET_FILE:test_shard_control>
        COMMAND $<TARGET_FILE:test_jit>
        COMMAND $<TARGET_FILE:test_serve_loader>
        COMMAND $<TARGET_FILE:test_reload_coordinator>
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test_process_reload.py --rut $<TARGET_FILE:rut>
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test_backend_selection.py --rut $<TARGET_FILE:rut>
        COMMAND $<TARGET_FILE:test_traffic_capture>
        COMMAND $<TARGET_FILE:test_traffic_replay>
        COMMAND $<TARGET_FILE:test_sim>
        COMMAND $<TARGET_FILE:test_simulate_engine>
        COMMAND $<TARGET_FILE:test_harness>
        COMMAND $<TARGET_FILE:test_route_trie>
        COMMAND $<TARGET_FILE:test_route_art>
        COMMAND $<TARGET_FILE:test_route_select>
        DEPENDS rut test_network test_integration test_arena test_expected test_http_parser test_http2 test_hpack test_hpack_diff test_http2_conn test_chunked_parser test_buffer test_cache_table test_hash_table test_types test_rir test_frontend test_drain test_access_log test_metrics test_debug test_fault_injection test_shard_control test_jit test_serve_loader test_reload_coordinator test_traffic_capture test_traffic_replay test_sim rut-simulate test_simulate_engine test_harness test_route_trie test_route_art test_route_select
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
        COMMAND $<TARGET_FILE:test_hash_table>
        COMMAND $<TARGET_FILE:test_types>
        COMMAND $<TARGET_FILE:test_rir>
        COMMAND $<TARGET_FILE:test_frontend>
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
        DEPENDS test_network test_integration test_arena test_expected test_http_parser test_http2 test_hpack test_hpack_diff test_http2_conn test_chunked_parser test_buffer test_cache_table test_hash_table test_types test_rir test_frontend test_drain test_access_log test_metrics test_debug test_fault_injection test_shard_control test_traffic_capture test_traffic_replay test_sim test_harness test_route_trie test_route_art test_route_select
        COMMENT "Running non-JIT tests..."
    )
endif()
