# Pin the runtime-free RE2 fork while keeping Rut's CMake 3.20 minimum.
# We build only the upstream library source list; its top-level project also
# configures tests and requires CMake 3.22.
include(FetchContent)
if(POLICY CMP0169)
    cmake_policy(SET CMP0169 OLD)
endif()
if(POLICY CMP0135)
    cmake_policy(SET CMP0135 NEW)
endif()

FetchContent_Declare(rut_re2
    URL https://codeload.github.com/rutlang-ai/re2/tar.gz/88190621fa40e3eeca8c337c4b1222f706440402
    URL_HASH SHA256=7838f989ed2a3d5f1cd45e14e77dc8091b78b6491d2449d45d88aab79d5d6d8a)
FetchContent_GetProperties(rut_re2)
if(NOT rut_re2_POPULATED)
    FetchContent_Populate(rut_re2)
endif()

set(_rut_re2_prog_source "${rut_re2_SOURCE_DIR}/re2/prog.cc")
set(_rut_re2_dfa_source "${rut_re2_SOURCE_DIR}/re2/dfa.cc")
if(APPLE AND CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    # libc++ routes default std::sort calls for char/int through explicit
    # __sort ABI instantiations in libc++. The no-stdlib server cannot link
    # those symbols, so use equivalent custom comparators in build-tree copies.
    # Keep the pinned archive pristine and fail if its exact call sites change.
    function(rut_re2_replace_once text_variable old new)
        set(source_text "${${text_variable}}")
        string(LENGTH "${source_text}" source_text_length)
        string(LENGTH "${old}" old_length)
        string(REPLACE "${old}" "" source_without_call "${source_text}")
        string(LENGTH "${source_without_call}" source_without_call_length)
        math(EXPR removed_length "${source_text_length}-${source_without_call_length}")
        if(NOT removed_length EQUAL old_length)
            message(FATAL_ERROR
                "Expected exactly one RE2 libc++ sort call '${old}'")
        endif()
        string(REPLACE "${old}" "${new}" source_text "${source_text}")
        set(${text_variable} "${source_text}" PARENT_SCOPE)
    endfunction()

    set(_rut_re2_libcxx_source_dir "${CMAKE_CURRENT_BINARY_DIR}/rut_re2_libcxx")
    file(MAKE_DIRECTORY "${_rut_re2_libcxx_source_dir}")
    set(_rut_re2_prog_source "${_rut_re2_libcxx_source_dir}/prog.cc")
    set(_rut_re2_dfa_source "${_rut_re2_libcxx_source_dir}/dfa.cc")
    file(READ "${rut_re2_SOURCE_DIR}/re2/prog.cc" _rut_re2_prog_text)
    rut_re2_replace_once(
        _rut_re2_prog_text
        "std::sort(prefix.begin(), prefix.end());"
        "std::sort(prefix.begin(), prefix.end(), [](char lhs, char rhs) { return lhs < rhs; });")
    file(WRITE "${_rut_re2_prog_source}" "${_rut_re2_prog_text}")
    set(_rut_re2_dfa_source_original "${rut_re2_SOURCE_DIR}/re2/dfa.cc")
    file(READ "${_rut_re2_dfa_source_original}" _rut_re2_dfa_text)
    rut_re2_replace_once(
        _rut_re2_dfa_text
        "std::sort(ip, markp);"
        "std::sort(ip, markp, [](int lhs, int rhs) { return lhs < rhs; });")
    rut_re2_replace_once(
        _rut_re2_dfa_text
        "std::sort(ip, ep);"
        "std::sort(ip, ep, [](int lhs, int rhs) { return lhs < rhs; });")
    file(WRITE "${_rut_re2_dfa_source}" "${_rut_re2_dfa_text}")
endif()

find_package(Threads REQUIRED)
add_library(re2 STATIC
    "${rut_re2_SOURCE_DIR}/re2/bitmap256.cc"
    "${rut_re2_SOURCE_DIR}/re2/bitstate.cc"
    "${rut_re2_SOURCE_DIR}/re2/compile.cc"
    "${_rut_re2_dfa_source}"
    "${rut_re2_SOURCE_DIR}/re2/filtered_re2.cc"
    "${rut_re2_SOURCE_DIR}/re2/mimics_pcre.cc"
    "${rut_re2_SOURCE_DIR}/re2/nfa.cc"
    "${rut_re2_SOURCE_DIR}/re2/onepass.cc"
    "${rut_re2_SOURCE_DIR}/re2/parse.cc"
    "${rut_re2_SOURCE_DIR}/re2/perl_groups.cc"
    "${rut_re2_SOURCE_DIR}/re2/prefilter.cc"
    "${rut_re2_SOURCE_DIR}/re2/prefilter_tree.cc"
    "${_rut_re2_prog_source}"
    "${rut_re2_SOURCE_DIR}/re2/re2.cc"
    "${rut_re2_SOURCE_DIR}/re2/regexp.cc"
    "${rut_re2_SOURCE_DIR}/re2/set.cc"
    "${rut_re2_SOURCE_DIR}/re2/simplify.cc"
    "${rut_re2_SOURCE_DIR}/re2/tostring.cc"
    "${rut_re2_SOURCE_DIR}/re2/unicode_casefold.cc"
    "${rut_re2_SOURCE_DIR}/re2/unicode_groups.cc"
    "${rut_re2_SOURCE_DIR}/util/rune.cc"
    "${rut_re2_SOURCE_DIR}/util/strutil.cc")
add_library(re2::re2 ALIAS re2)
target_compile_features(re2 PUBLIC cxx_std_20)
target_include_directories(re2 PUBLIC "${rut_re2_SOURCE_DIR}")
target_compile_options(re2 PRIVATE -fno-exceptions -fno-rtti)
target_compile_definitions(re2 PRIVATE _GLIBCXX_NO_ASSERTIONS)
if(APPLE AND CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    # Containa's btree_map.hpp uses std::abort without including <cstdlib>.
    # libc++ does not expose it through the C header <stdlib.h>.
    target_compile_options(re2 PRIVATE -include cstdlib)
endif()
target_link_libraries(re2 PUBLIC Threads::Threads)
# Keep the fork's global allocator/guard definitions out of C++-linked tools.
if(RUT_ENABLE_JIT AND NOT RUT_SANITIZE)
    add_library(rut_re2_runtime OBJECT "${rut_re2_SOURCE_DIR}/re2/runtime.cc")
    target_compile_features(rut_re2_runtime PRIVATE cxx_std_20)
    target_compile_options(rut_re2_runtime PRIVATE -fno-exceptions -fno-rtti)
    target_compile_definitions(rut_re2_runtime PRIVATE _GLIBCXX_NO_ASSERTIONS)
endif()
if(NOT UNIX)
    message(FATAL_ERROR "The runtime-free RE2 port currently supports POSIX systems")
endif()
