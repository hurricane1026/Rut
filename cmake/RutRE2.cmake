# Temporary upstream capture backend. Keep RE2/Abseil behind rut_regex_capture
# so a future replacement does not change compiler or native-helper callers.
include(FetchContent)
if(POLICY CMP0169)
    # The older Populate + add_subdirectory form is required for CMake 3.20
    # compatibility because EXCLUDE_FROM_ALL is not available on MakeAvailable.
    cmake_policy(SET CMP0169 OLD)
endif()
function(rut_configure_re2)
    set(BUILD_SHARED_LIBS OFF)
    set(ABSL_BUILD_TESTING OFF CACHE BOOL "" FORCE)
    set(ABSL_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)
    set(ABSL_PROPAGATE_CXX_STD ON CACHE BOOL "" FORCE)
    set(RE2_INSTALL OFF CACHE BOOL "" FORCE)
    set(RE2_BUILD_TESTING OFF CACHE BOOL "" FORCE)
    set(RE2_USE_ICU OFF CACHE BOOL "" FORCE)
    if(POLICY CMP0135)
        cmake_policy(SET CMP0135 NEW)
    endif()
    FetchContent_Declare(rut_abseil
        URL https://codeload.github.com/abseil/abseil-cpp/tar.gz/refs/tags/20250814.1
        URL_HASH SHA256=1692f77d1739bacf3f94337188b78583cf09bab7e420d2dc6c5605a4f86785a1)
    # The bundled Abseil source tree defines optional targets beyond RE2's
    # transitive link dependencies. Keep unrelated targets out of the default
    # build while still building everything RE2 requires.
    FetchContent_GetProperties(rut_abseil)
    if(NOT rut_abseil_POPULATED)
        FetchContent_Populate(rut_abseil)
        add_subdirectory("${rut_abseil_SOURCE_DIR}" "${rut_abseil_BINARY_DIR}" EXCLUDE_FROM_ALL)
    endif()
    FetchContent_Declare(rut_re2
        URL https://github.com/google/re2/releases/download/2025-11-05/re2-2025-11-05.tar.gz
        URL_HASH SHA256=87f6029d2f6de8aa023654240a03ada90e876ce9a4676e258dd01ea4c26ffd67)
    FetchContent_GetProperties(rut_re2)
    if(NOT rut_re2_POPULATED)
        FetchContent_Populate(rut_re2)
        add_subdirectory("${rut_re2_SOURCE_DIR}" "${rut_re2_BINARY_DIR}" EXCLUDE_FROM_ALL)
    endif()
    if(RUT_SANITIZE AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        if(NOT TARGET absl_flags_reflection OR NOT TARGET re2)
            message(FATAL_ERROR "Expected RE2 and Abseil targets for the GCC UBSan workaround")
        endif()
        # GCC's UBSan instrumentation makes Abseil's constexpr comparison of
        # type-erased function pointers non-constant (GCC bug 71962). This
        # affects Abseil reflection and RE2's flat-hash instantiations. Keep
        # ASan and every other UBSan check enabled on these third-party targets.
        target_compile_options(absl_flags_reflection PRIVATE
            -fno-sanitize=null,nonnull-attribute,returns-nonnull-attribute)
        target_compile_options(re2 PRIVATE
            -fno-sanitize=null,nonnull-attribute,returns-nonnull-attribute)
    endif()
endfunction()
rut_configure_re2()
