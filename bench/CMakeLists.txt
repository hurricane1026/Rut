# llhttp (Node.js HTTP parser) — compiled as C
add_library(llhttp STATIC
    ${PROJECT_SOURCE_DIR}/third_party/llhttp/src/llhttp.c
    ${PROJECT_SOURCE_DIR}/third_party/llhttp/src/api.c
    ${PROJECT_SOURCE_DIR}/third_party/llhttp/src/http.c
)
target_include_directories(llhttp PUBLIC
    ${PROJECT_SOURCE_DIR}/third_party/llhttp/include
)
# llhttp is C, not C++ — override flags
set_target_properties(llhttp PROPERTIES
    LINKER_LANGUAGE C
)
target_compile_options(llhttp PRIVATE -O2 -DNDEBUG)

# Benchmark executables
add_executable(bench_http_parser bench_http_parser.cc)
target_link_libraries(bench_http_parser rut_runtime llhttp)
target_include_directories(bench_http_parser PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/testing
    ${PROJECT_SOURCE_DIR}/third_party/llhttp/include
)

add_executable(bench_connection bench_connection.cc)
target_link_libraries(bench_connection rut_runtime)
target_include_directories(bench_connection PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/testing
)

# HTTP/2 HPACK + framing hot paths. Links the vendored nghttp2 reference for a
# decode baseline (rut vs nghttp2), mirroring bench_http_parser vs llhttp.
add_executable(bench_hpack bench_hpack.cc)
target_link_libraries(bench_hpack rut_runtime nghttp2_ref)
target_include_directories(bench_hpack PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/testing
)
target_compile_options(bench_hpack PRIVATE -O3 -DNDEBUG)

# JIT-specialized ART vs scalar ART, exercising both the direct JIT
# function pointer and the productized RouteConfig dispatch paths.
if(RUT_ENABLE_JIT)
    add_executable(bench_art_jit_spike bench_art_jit_spike.cc)
    target_link_libraries(bench_art_jit_spike rut_runtime rut_jit)
    target_include_directories(bench_art_jit_spike PRIVATE
        ${PROJECT_SOURCE_DIR}/include
        ${PROJECT_SOURCE_DIR}/testing
        ${LLVM_INCLUDE_DIRS}
    )
    target_compile_definitions(bench_art_jit_spike PRIVATE ${LLVM_DEFINITIONS})
    target_compile_options(bench_art_jit_spike PRIVATE -O3 -DNDEBUG)
endif()

# Parser SIMD scan_uri vs scalar reference. Selected SIMD backend is
# fixed at build time via -DSIMD_ARCH=<avx512|avx2|sse2|neon|sve|scalar>.
# The bench compiles SIMD_FLAGS through so the backend's intrinsics
# match the rut_runtime build, and adds the simd/ private include
# directory for char_tables.h (kUriTable used by the scalar reference).
add_executable(bench_scan_uri bench_scan_uri.cc)
target_link_libraries(bench_scan_uri rut_runtime)
target_include_directories(bench_scan_uri PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/src
    ${PROJECT_SOURCE_DIR}/src/runtime/simd
    ${PROJECT_SOURCE_DIR}/testing
)
target_compile_options(bench_scan_uri PRIVATE -O3 -DNDEBUG ${SIMD_FLAGS})
# Pass the resolved SIMD backend name so the bench's banner reflects the
# actual scan_uri linked into the binary. ifdef'ing on compiler-time
# macros (__AVX2__, __ARM_NEON, …) doesn't work because some are
# baseline on their target ISA (NEON is always defined on aarch64,
# SSE2 on x86_64), so a SIMD_ARCH=scalar build would still report
# the baseline ISA name.
target_compile_definitions(bench_scan_uri PRIVATE BENCH_SIMD_BACKEND="${SIMD_ARCH}")

# Dispatch comparison — linear scan vs scalar ART vs JIT ART, sweeping
# route count and hit position. Runs in CI alongside bench_scan_uri so
# the JIT-vs-linear speedup is reported per-architecture (sse2/avx2/
# avx512 on x86, neon on arm64) — same hardware-gating pattern as the
# scan_uri job means an Intel runner with avx512f would pick that up
# automatically.
if(RUT_ENABLE_JIT)
    add_executable(bench_dispatch_compare bench_dispatch_compare.cc)
    target_link_libraries(bench_dispatch_compare rut_runtime rut_jit)
    target_include_directories(bench_dispatch_compare PRIVATE
        ${PROJECT_SOURCE_DIR}/include
        ${PROJECT_SOURCE_DIR}/testing
        ${LLVM_INCLUDE_DIRS}
    )
    target_compile_definitions(bench_dispatch_compare PRIVATE
        ${LLVM_DEFINITIONS}
        BENCH_SIMD_BACKEND="${SIMD_ARCH}"
    )
    target_compile_options(bench_dispatch_compare PRIVATE -O3 -DNDEBUG ${SIMD_FLAGS})
endif()
