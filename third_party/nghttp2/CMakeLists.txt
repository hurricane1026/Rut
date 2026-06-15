# nghttp2 core library (v1.62.1), vendored as a REFERENCE for differential
# correctness tests and benchmark baselines only. NOT linked into the rut
# runtime. The HPACK + framing core is dependency-free C; config.h is guarded
# behind HAVE_CONFIG_H (left undefined) so none is needed.
file(GLOB NGHTTP2_REF_SRC ${CMAKE_CURRENT_SOURCE_DIR}/lib/*.c)

add_library(nghttp2_ref STATIC ${NGHTTP2_REF_SRC})
target_include_directories(nghttp2_ref PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/includes
    ${CMAKE_CURRENT_SOURCE_DIR}/lib
)
target_compile_definitions(nghttp2_ref PUBLIC NGHTTP2_STATICLIB)
set_target_properties(nghttp2_ref PROPERTIES LINKER_LANGUAGE C)
# Third-party source: do not apply the project's -Werror / warning set.
# Force-include arpa/inet.h for htonl/htons/ntohl/ntohs — nghttp2 normally
# pulls these via a generated config.h, which we deliberately omit.
target_compile_options(nghttp2_ref PRIVATE -O2 -w -include arpa/inet.h)
