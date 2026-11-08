# RFC 7692 requires raw DEFLATE; the existing compress-only zstd cannot supply it.
# Build only the codec, without gzip files, host discovery, or default allocators.
include(FetchContent)
if(POLICY CMP0135)
    cmake_policy(SET CMP0135 NEW)
endif()
FetchContent_Declare(rut_ws_zlib_source
    # The release asset ID is a stable API path used only if the release URL fails.
    URL
        https://github.com/madler/zlib/releases/download/v1.3.2/zlib-1.3.2.tar.gz
        https://api.github.com/repos/madler/zlib/releases/assets/357391855
    HTTP_HEADER "Accept: application/octet-stream"
    URL_HASH SHA256=bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16
    SOURCE_SUBDIR rut_source_only
)
FetchContent_MakeAvailable(rut_ws_zlib_source)
add_library(rut_ws_zlib STATIC
    ${rut_ws_zlib_source_SOURCE_DIR}/adler32.c
    ${rut_ws_zlib_source_SOURCE_DIR}/crc32.c
    ${rut_ws_zlib_source_SOURCE_DIR}/deflate.c
    ${rut_ws_zlib_source_SOURCE_DIR}/inflate.c
    ${rut_ws_zlib_source_SOURCE_DIR}/inffast.c
    ${rut_ws_zlib_source_SOURCE_DIR}/inftrees.c
    ${rut_ws_zlib_source_SOURCE_DIR}/trees.c
    ${rut_ws_zlib_source_SOURCE_DIR}/zutil.c
)
target_compile_definitions(rut_ws_zlib PRIVATE Z_SOLO Z_PREFIX ZLIB_CONST)
target_include_directories(rut_ws_zlib SYSTEM PUBLIC ${rut_ws_zlib_source_SOURCE_DIR})
