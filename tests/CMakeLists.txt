add_executable(test_framework test_framework.cc)
target_include_directories(test_framework PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/testing
)
add_test(NAME test_framework COMMAND test_framework)
set_tests_properties(test_framework PROPERTIES WILL_FAIL TRUE)

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
add_test(NAME test_integration COMMAND test_integration)
set_tests_properties(test_integration PROPERTIES LABELS "integration;network" TIMEOUT 300)

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
    add_dependencies(test_nginx_differential rut test_nginx_downstream_gate_preload)
    if(TARGET test_rut_iouring_gate_preload)
        add_dependencies(test_nginx_differential test_rut_iouring_gate_preload)
    endif()
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
    target_link_libraries(test_serve_loader rut_loader)
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
