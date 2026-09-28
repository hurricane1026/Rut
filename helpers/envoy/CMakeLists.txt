cmake_minimum_required(VERSION 3.20)

# Also buildable directly: cmake -S helpers/envoy -B build-envoy-helper.
# No LLVM, gateway runtime, or Rut compiler library is needed by this helper.
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    project(rut_envoy_helper LANGUAGES CXX)
    set(CMAKE_CXX_STANDARD 23)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
    set(CMAKE_CXX_EXTENSIONS OFF)
    add_compile_options(-fno-exceptions -fno-rtti -Wall -Wextra -Wpedantic)
endif()

get_filename_component(RUT_ENVOY_REPO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
add_library(rut_envoy STATIC json.cc parser.cc converter.cc)
target_include_directories(rut_envoy PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${RUT_ENVOY_REPO_ROOT}/include
)
add_executable(rut-envoy-convert main.cc ${RUT_ENVOY_REPO_ROOT}/src/placement_new.cc)
target_link_libraries(rut-envoy-convert PRIVATE rut_envoy)
