# Temporary upstream capture backend. Keep RE2/Abseil behind rut_regex_capture
# so a future replacement does not change compiler or native-helper callers.
include(FetchContent)
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
    FetchContent_MakeAvailable(rut_abseil)
    FetchContent_Declare(rut_re2
        URL https://github.com/google/re2/releases/download/2025-11-05/re2-2025-11-05.tar.gz
        URL_HASH SHA256=87f6029d2f6de8aa023654240a03ada90e876ce9a4676e258dd01ea4c26ffd67)
    FetchContent_MakeAvailable(rut_re2)
endfunction()
rut_configure_re2()
