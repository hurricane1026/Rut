# Portable targets are registered in CMakeLists.txt on both platforms.
add_executable(test_kqueue test_kqueue.cc)
target_link_libraries(test_kqueue PRIVATE rut_test_fault rut_runtime)
target_include_directories(test_kqueue PRIVATE ${PROJECT_SOURCE_DIR}/testing)
add_test(NAME test_kqueue COMMAND test_kqueue)
set_tests_properties(test_kqueue PROPERTIES LABELS "unit;macos" TIMEOUT 120)

if(RUT_ENABLE_JIT)
    add_test(NAME test_macos_server
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test_macos_server.py
            $<TARGET_FILE:rut> ${CMAKE_CURRENT_SOURCE_DIR}/fixtures)
    set_tests_properties(test_macos_server PROPERTIES LABELS "integration;macos" TIMEOUT 90)
endif()

get_property(_rut_test_targets DIRECTORY PROPERTY BUILDSYSTEM_TARGETS)
add_custom_target(check
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure --no-tests=error
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    DEPENDS ${_rut_test_targets}
    USES_TERMINAL)
