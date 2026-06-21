# SIMD architecture selection
set(SIMD_ARCH "auto" CACHE STRING "SIMD architecture: auto, scalar, sse2, avx2, avx512, neon, sve")
set_property(CACHE SIMD_ARCH PROPERTY STRINGS auto scalar sse2 avx2 avx512 neon sve)

# Temporarily disable testing while configuring BoringSSL so its internal
# test targets do not affect the rest of the project.
if(DEFINED BUILD_TESTING)
    set(_BORINGSSL_PREV_BUILD_TESTING_DEFINED TRUE)
    set(_BORINGSSL_PREV_BUILD_TESTING "${BUILD_TESTING}")
else()
    set(_BORINGSSL_PREV_BUILD_TESTING_DEFINED FALSE)
endif()
set(BUILD_TESTING OFF)
add_subdirectory(${PROJECT_SOURCE_DIR}/third_party/boringssl
    ${CMAKE_CURRENT_BINARY_DIR}/third_party/boringssl
    EXCLUDE_FROM_ALL
)
if(_BORINGSSL_PREV_BUILD_TESTING_DEFINED)
    set(BUILD_TESTING "${_BORINGSSL_PREV_BUILD_TESTING}")
else()
    unset(BUILD_TESTING)
endif()
unset(_BORINGSSL_PREV_BUILD_TESTING_DEFINED)
unset(_BORINGSSL_PREV_BUILD_TESTING)
foreach(BORINGSSL_TARGET fipsmodule crypto ssl decrepit pki)
    if(TARGET ${BORINGSSL_TARGET})
        # BoringSSL is third-party; silence its warning noise entirely
        # rather than just demoting from error to warning. Earlier we
        # only had -Wno-error=... which still printed thousands of
        # -Wunused-parameter lines on every build (4000+ in CI logs,
        # mostly from internal.h macro expansions). The full -Wno-...
        # form suppresses the warning, not just the error promotion.
        target_compile_options(${BORINGSSL_TARGET} PRIVATE
            -Wno-error
            -Wno-pedantic
            -Wno-unused-parameter
        )
    endif()
endforeach()

if(SIMD_ARCH STREQUAL "auto")
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|ARM64")
        set(SIMD_ARCH "neon")
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|amd64")
        # SSE2 is the x86_64 ISA baseline — every x86_64 CPU has it,
        # so a binary built with auto stays portable across mixed
        # fleets and cross-compile scenarios. Production server
        # deployments should set -DSIMD_ARCH=avx2 explicitly: AVX2
        # wins SSE2 by 2-4x on scan_uri (see DISPATCH_PERF.md), and
        # every server-class CPU since Haswell (2013) supports it.
        # AVX-512 is opt-in only — see DISPATCH_PERF.md for the
        # frequency-throttling caveats that make it a poor default.
        set(SIMD_ARCH "sse2")
    else()
        set(SIMD_ARCH "scalar")
    endif()
endif()

message(STATUS "SIMD backend: ${SIMD_ARCH}")

if(SIMD_ARCH STREQUAL "avx512")
    set(SIMD_SOURCE runtime/simd/avx512.cc)
    set(SIMD_FLAGS "-mavx512f;-mavx512bw")
elseif(SIMD_ARCH STREQUAL "avx2")
    set(SIMD_SOURCE runtime/simd/avx2.cc)
    set(SIMD_FLAGS "-mavx2")
elseif(SIMD_ARCH STREQUAL "sse2")
    set(SIMD_SOURCE runtime/simd/sse2.cc)
    set(SIMD_FLAGS "-msse2")
elseif(SIMD_ARCH STREQUAL "neon")
    set(SIMD_SOURCE runtime/simd/neon.cc)
    set(SIMD_FLAGS "")
elseif(SIMD_ARCH STREQUAL "sve")
    set(SIMD_SOURCE runtime/simd/sve.cc)
    set(SIMD_FLAGS "-march=armv8-a+sve")
elseif(SIMD_ARCH STREQUAL "scalar")
    set(SIMD_SOURCE runtime/simd/scalar.cc)
    set(SIMD_FLAGS "")
else()
    message(FATAL_ERROR "Unknown SIMD_ARCH '${SIMD_ARCH}'. Valid options: auto, scalar, sse2, avx2, avx512, neon, sve")
endif()

# Propagate the resolved SIMD configuration to the parent scope so
# sibling subdirectories (bench/, tests/) can compile against the same
# backend — bench_scan_uri specifically needs SIMD_FLAGS so the
# __AVX2__/__AVX512F__ predefines match the rut_runtime build.
set(SIMD_ARCH "${SIMD_ARCH}" PARENT_SCOPE)
set(SIMD_FLAGS "${SIMD_FLAGS}" PARENT_SCOPE)

find_package(Threads REQUIRED)

# zstd — vendored, compress only, stripped strategies (fast + doubleFast only).
# Excludes greedy/lazy/btlazy2/btopt/btultra to keep binary small (~120KB vs ~400KB).
# Level 1-4 use fast, level 5 uses doubleFast. Higher levels are unsupported.
set(ZSTD_DIR ${PROJECT_SOURCE_DIR}/third_party/zstd/lib)
add_library(zstd_compress STATIC
    ${ZSTD_DIR}/compress/zstd_compress.c
    ${ZSTD_DIR}/compress/zstd_compress_literals.c
    ${ZSTD_DIR}/compress/zstd_compress_sequences.c
    ${ZSTD_DIR}/compress/zstd_compress_superblock.c
    ${ZSTD_DIR}/compress/zstd_fast.c
    ${ZSTD_DIR}/compress/zstd_double_fast.c
    ${ZSTD_DIR}/compress/zstd_lazy.c
    ${ZSTD_DIR}/compress/zstd_opt.c
    ${ZSTD_DIR}/compress/zstd_ldm.c
    ${ZSTD_DIR}/compress/zstd_preSplit.c
    ${ZSTD_DIR}/compress/fse_compress.c
    ${ZSTD_DIR}/compress/huf_compress.c
    ${ZSTD_DIR}/compress/hist.c
    ${ZSTD_DIR}/common/zstd_common.c
    ${ZSTD_DIR}/common/entropy_common.c
    ${ZSTD_DIR}/common/error_private.c
    ${ZSTD_DIR}/common/debug.c
    ${ZSTD_DIR}/common/xxhash.c
    ${ZSTD_DIR}/common/fse_decompress.c
)
target_include_directories(zstd_compress PUBLIC ${ZSTD_DIR} ${ZSTD_DIR}/common)
set_target_properties(zstd_compress PROPERTIES LANGUAGE C)
target_compile_options(zstd_compress PRIVATE
    -O2 -DNDEBUG
    -DZSTD_EXCLUDE_GREEDY_BLOCK_COMPRESSOR
    -DZSTD_EXCLUDE_LAZY_BLOCK_COMPRESSOR
    -DZSTD_EXCLUDE_LAZY2_BLOCK_COMPRESSOR
    -DZSTD_EXCLUDE_BTLAZY2_BLOCK_COMPRESSOR
    -DZSTD_EXCLUDE_BTOPT_BLOCK_COMPRESSOR
    -DZSTD_EXCLUDE_BTULTRA_BLOCK_COMPRESSOR
    -ffunction-sections -fdata-sections
)

# Runtime library
add_library(rut_runtime STATIC
    placement_new.cc
    runtime/arena.cc
    runtime/callbacks.cc
    runtime/shard.cc
    runtime/io_uring_backend.cc
    runtime/epoll_backend.cc
    runtime/timer_wheel.cc
    runtime/socket.cc
    runtime/tls.cc
    runtime/tls_engine.cc
    runtime/http_parser.cc
    runtime/http2_frame.cc
    runtime/http2_conn.cc
    runtime/hpack.cc
    runtime/chunked_parser.cc
    runtime/ws_frame.cc
    runtime/ws_terminate.cc
    runtime/access_log.cc
    runtime/traffic_capture.cc
    runtime/route_art.cc
    runtime/route_select.cc
    runtime/route_trie.cc
    ${SIMD_SOURCE}
)

target_include_directories(rut_runtime PUBLIC
    ${PROJECT_SOURCE_DIR}/include
)

# Make ignoring a [[nodiscard]] result a hard error in the runtime — the automated
# guard for the fail-closed invariant on the io_uring async-pause helpers
# (pause_upstream_recv / _for_send / pause_recv / ws_pause_upstream_recv): they
# return false when a cancel SQE can't queue under SQ pressure, and every caller
# must fail closed. callbacks.cc explicitly instantiates the pause callers
# (on_response_body_recvd<IoUringEventLoop> etc.), so a future commit that ignores a
# result fails to compile here. Scoped to this target (not global): glibc marks
# write()/read() warn_unused_result at -O2, and GCC does NOT honor a (void) cast on
# those, so a blanket flag would break the test/bench harness and third_party — the
# runtime itself is warn_unused_result-clean.
target_compile_options(rut_runtime PRIVATE -Werror=unused-result)
target_link_libraries(rut_runtime
    zstd_compress
    ssl
    crypto
    Threads::Threads
)

# SIMD source needs to find simd.h and char_tables.h via "simd.h" include
target_include_directories(rut_runtime PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/runtime/simd
)

# Apply ISA-specific flags only to the SIMD translation unit
if(SIMD_FLAGS)
    set_source_files_properties(${SIMD_SOURCE}
        PROPERTIES COMPILE_OPTIONS "${SIMD_FLAGS}"
    )
endif()

# Compiler library
add_library(rut_compiler STATIC
    compiler/lexer.cc
    compiler/parser.cc
    compiler/analyze.cc
    compiler/mir_build.cc
    compiler/lower_rir.cc
    compiler/rir_printer.cc
)

target_include_directories(rut_compiler PUBLIC
    ${PROJECT_SOURCE_DIR}/include
)

if(RUT_ENABLE_JIT)
    # Vectorscan/Hyperscan regex backend. Build only the static library and disable
    # extra targets; Rut links it into rut_jit for regex compilation and scanning.
    # Vectorscan's CMake mutates global flags, so isolate it between save/restore.
    set(_RUT_SAVE_CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
    set(_RUT_SAVE_CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
    set(_RUT_SAVE_CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")
    set(_RUT_SAVE_CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")
    set(_RUT_SAVE_CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE}")
    set(_RUT_SAVE_CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")
    set(_RUT_SAVE_CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELWITHDEBINFO}")
    set(_RUT_SAVE_CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO}")
    set(_RUT_SAVE_CMAKE_C_FLAGS_MINSIZEREL "${CMAKE_C_FLAGS_MINSIZEREL}")
    set(_RUT_SAVE_CMAKE_CXX_FLAGS_MINSIZEREL "${CMAKE_CXX_FLAGS_MINSIZEREL}")
    set(_RUT_SAVE_CMAKE_CXX_STANDARD "${CMAKE_CXX_STANDARD}")
    set(_RUT_SAVE_CMAKE_CXX_EXTENSIONS "${CMAKE_CXX_EXTENSIONS}")
    set(_RUT_SAVE_CCACHE_DISABLE "$ENV{CCACHE_DISABLE}")
    get_property(_RUT_SAVE_RULE_LAUNCH_COMPILE GLOBAL PROPERTY RULE_LAUNCH_COMPILE)
    get_property(_RUT_SAVE_RULE_LAUNCH_LINK GLOBAL PROPERTY RULE_LAUNCH_LINK)
    foreach(_RUT_VS_CACHE_VAR
            BUILD_STATIC_LIBS
            BUILD_SHARED_LIBS
            BUILD_UNIT
            BUILD_TOOLS
            BUILD_EXAMPLES
            BUILD_BENCHMARKS
            FAT_RUNTIME
            DUMP_SUPPORT)
        if(DEFINED CACHE{${_RUT_VS_CACHE_VAR}})
            set("_RUT_SAVE_${_RUT_VS_CACHE_VAR}_DEFINED" TRUE)
            get_property("_RUT_SAVE_${_RUT_VS_CACHE_VAR}_VALUE"
                CACHE "${_RUT_VS_CACHE_VAR}" PROPERTY VALUE)
            get_property("_RUT_SAVE_${_RUT_VS_CACHE_VAR}_TYPE"
                CACHE "${_RUT_VS_CACHE_VAR}" PROPERTY TYPE)
            get_property("_RUT_SAVE_${_RUT_VS_CACHE_VAR}_HELP"
                CACHE "${_RUT_VS_CACHE_VAR}" PROPERTY HELPSTRING)
        else()
            set("_RUT_SAVE_${_RUT_VS_CACHE_VAR}_DEFINED" FALSE)
        endif()
    endforeach()
    set(ENV{CCACHE_DISABLE} "1")
    set(CMAKE_C_FLAGS "")
    set(CMAKE_CXX_FLAGS "")
    set(CMAKE_C_FLAGS_DEBUG "")
    set(CMAKE_CXX_FLAGS_DEBUG "")
    set(CMAKE_C_FLAGS_RELEASE "")
    set(CMAKE_CXX_FLAGS_RELEASE "")
    set(CMAKE_C_FLAGS_RELWITHDEBINFO "")
    set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "")
    set(CMAKE_C_FLAGS_MINSIZEREL "")
    set(CMAKE_CXX_FLAGS_MINSIZEREL "")
    set(CMAKE_CXX_STANDARD 17)
    set(CMAKE_CXX_EXTENSIONS ON)
    set(BUILD_STATIC_LIBS ON CACHE BOOL "Build vectorscan static libraries" FORCE)
    set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build vectorscan shared libraries" FORCE)
    set(BUILD_UNIT OFF CACHE BOOL "Build vectorscan unit tests" FORCE)
    set(BUILD_TOOLS OFF CACHE BOOL "Build vectorscan tools" FORCE)
    set(BUILD_EXAMPLES OFF CACHE BOOL "Build vectorscan examples" FORCE)
    set(BUILD_BENCHMARKS OFF CACHE BOOL "Build vectorscan benchmarks" FORCE)
    set(FAT_RUNTIME OFF CACHE BOOL "Build vectorscan fat runtime" FORCE)
    set(DUMP_SUPPORT OFF CACHE BOOL "Build vectorscan dump support" FORCE)
    add_subdirectory(${PROJECT_SOURCE_DIR}/third_party/vectorscan
        ${CMAKE_CURRENT_BINARY_DIR}/third_party/vectorscan
        EXCLUDE_FROM_ALL
    )
    set(CMAKE_C_FLAGS "${_RUT_SAVE_CMAKE_C_FLAGS}")
    set(CMAKE_CXX_FLAGS "${_RUT_SAVE_CMAKE_CXX_FLAGS}")
    set(CMAKE_C_FLAGS_DEBUG "${_RUT_SAVE_CMAKE_C_FLAGS_DEBUG}")
    set(CMAKE_CXX_FLAGS_DEBUG "${_RUT_SAVE_CMAKE_CXX_FLAGS_DEBUG}")
    set(CMAKE_C_FLAGS_RELEASE "${_RUT_SAVE_CMAKE_C_FLAGS_RELEASE}")
    set(CMAKE_CXX_FLAGS_RELEASE "${_RUT_SAVE_CMAKE_CXX_FLAGS_RELEASE}")
    set(CMAKE_C_FLAGS_RELWITHDEBINFO "${_RUT_SAVE_CMAKE_C_FLAGS_RELWITHDEBINFO}")
    set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${_RUT_SAVE_CMAKE_CXX_FLAGS_RELWITHDEBINFO}")
    set(CMAKE_C_FLAGS_MINSIZEREL "${_RUT_SAVE_CMAKE_C_FLAGS_MINSIZEREL}")
    set(CMAKE_CXX_FLAGS_MINSIZEREL "${_RUT_SAVE_CMAKE_CXX_FLAGS_MINSIZEREL}")
    set(CMAKE_CXX_STANDARD "${_RUT_SAVE_CMAKE_CXX_STANDARD}")
    set(CMAKE_CXX_EXTENSIONS "${_RUT_SAVE_CMAKE_CXX_EXTENSIONS}")
    foreach(_RUT_VS_CACHE_VAR
            BUILD_STATIC_LIBS
            BUILD_SHARED_LIBS
            BUILD_UNIT
            BUILD_TOOLS
            BUILD_EXAMPLES
            BUILD_BENCHMARKS
            FAT_RUNTIME
            DUMP_SUPPORT)
        if(_RUT_SAVE_${_RUT_VS_CACHE_VAR}_DEFINED)
            set("${_RUT_VS_CACHE_VAR}" "${_RUT_SAVE_${_RUT_VS_CACHE_VAR}_VALUE}"
                CACHE "${_RUT_SAVE_${_RUT_VS_CACHE_VAR}_TYPE}"
                "${_RUT_SAVE_${_RUT_VS_CACHE_VAR}_HELP}" FORCE)
        else()
            unset("${_RUT_VS_CACHE_VAR}" CACHE)
        endif()
        unset("_RUT_SAVE_${_RUT_VS_CACHE_VAR}_DEFINED")
        unset("_RUT_SAVE_${_RUT_VS_CACHE_VAR}_VALUE")
        unset("_RUT_SAVE_${_RUT_VS_CACHE_VAR}_TYPE")
        unset("_RUT_SAVE_${_RUT_VS_CACHE_VAR}_HELP")
    endforeach()
    unset(_RUT_VS_CACHE_VAR)
    set(ENV{CCACHE_DISABLE} "${_RUT_SAVE_CCACHE_DISABLE}")
    set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE "${_RUT_SAVE_RULE_LAUNCH_COMPILE}")
    set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK "${_RUT_SAVE_RULE_LAUNCH_LINK}")
    unset(_RUT_SAVE_CMAKE_C_FLAGS)
    unset(_RUT_SAVE_CMAKE_CXX_FLAGS)
    unset(_RUT_SAVE_CMAKE_C_FLAGS_DEBUG)
    unset(_RUT_SAVE_CMAKE_CXX_FLAGS_DEBUG)
    unset(_RUT_SAVE_CMAKE_C_FLAGS_RELEASE)
    unset(_RUT_SAVE_CMAKE_CXX_FLAGS_RELEASE)
    unset(_RUT_SAVE_CMAKE_C_FLAGS_RELWITHDEBINFO)
    unset(_RUT_SAVE_CMAKE_CXX_FLAGS_RELWITHDEBINFO)
    unset(_RUT_SAVE_CMAKE_C_FLAGS_MINSIZEREL)
    unset(_RUT_SAVE_CMAKE_CXX_FLAGS_MINSIZEREL)
    unset(_RUT_SAVE_CMAKE_CXX_STANDARD)
    unset(_RUT_SAVE_CMAKE_CXX_EXTENSIONS)
    unset(_RUT_SAVE_CCACHE_DISABLE)
    unset(_RUT_SAVE_RULE_LAUNCH_COMPILE)
    unset(_RUT_SAVE_RULE_LAUNCH_LINK)

    # JIT library — LLVM ORC JIT integration via C API.
    # Only this library links LLVM. rut_runtime stays LLVM-free so shard
    # threads never transitively depend on LLVM headers or libraries.
    add_library(rut_jit STATIC
        jit/jit_engine.cc
        jit/codegen.cc
        jit/art_jit_codegen.cc
        jit/runtime_helpers.cc
    )

    target_include_directories(rut_jit PUBLIC
        ${PROJECT_SOURCE_DIR}/include
        ${PROJECT_SOURCE_DIR}/third_party/vectorscan/src
        ${PROJECT_BINARY_DIR}/src/third_party/vectorscan
        ${PROJECT_SOURCE_DIR}/third_party/vectorscan/include
        ${LLVM_INCLUDE_DIRS}
    )

    # Prefer the monolithic shared LLVM dylib when the packaged config exposes it.
    # This avoids depending on broken per-component static archives in environments
    # where LLVM is installed in shared mode.
    if(LLVM_LINK_LLVM_DYLIB AND TARGET LLVM)
        set(LLVM_LIBS LLVM)
    else()
        # `passes` provides the new pass-manager C API (LLVMRunPasses /
        # LLVMCreatePassBuilderOptions) used by the JIT optimization pipeline;
        # `target` provides TargetMachine creation. Required for static LLVM
        # installs where these aren't pulled in transitively.
        llvm_map_components_to_libnames(LLVM_LIBS
            core orcjit orcshared orctargetprocess native support passes target)
    endif()
    target_link_libraries(rut_jit ${LLVM_LIBS})

    # JIT .cc files may need LLVM definitions that conflict with -fno-rtti.
    # The LLVM C API is pure C so no RTTI issues, but LLVM's cmake may add
    # -fno-rtti to definitions. Add LLVM definitions selectively.
    target_compile_definitions(rut_jit PRIVATE ${LLVM_DEFINITIONS})

    # rut_jit also links rut_runtime for runtime_helpers (uses HttpParser, Connection)
    target_link_libraries(rut_jit rut_runtime hs)
    target_include_directories(rut_compiler PRIVATE
        ${PROJECT_SOURCE_DIR}/third_party/vectorscan/src
        ${PROJECT_BINARY_DIR}/src/third_party/vectorscan
        ${PROJECT_SOURCE_DIR}/third_party/vectorscan/include
    )
    target_compile_definitions(rut_compiler PUBLIC RUT_VALIDATE_REGEX_WITH_VECTORSCAN=1)
    target_link_libraries(rut_compiler PUBLIC hs)

    # Offline simulate library — JIT-backed capture validation with no event loop.
    add_library(rut_simulate STATIC
        sim/simulate_engine.cc
    )
    target_include_directories(rut_simulate PUBLIC
        ${PROJECT_SOURCE_DIR}/include
        ${LLVM_INCLUDE_DIRS}
    )
    target_compile_definitions(rut_simulate PRIVATE ${LLVM_DEFINITIONS})
    target_link_libraries(rut_simulate
        rut_runtime
        rut_compiler
        rut_jit
    )

    add_executable(rut-simulate sim/main.cc)
    target_link_libraries(rut-simulate
        rut_simulate
    )
endif()

# Main executable. Keep this outside RUT_ENABLE_JIT so disabling LLVM/Vectorscan
# only omits the JIT-specific libraries and tools, not the primary server binary.
add_executable(rut main.cc)
target_link_libraries(rut
    rut_runtime
    rut_compiler
)

# When the JIT is built, the server can compile and serve a .rut program
# end to end. serve_loader.cc bridges frontend → JIT → RouteConfig; it
# pulls in rut_jit (and thus LLVM). Without the JIT the binary still
# builds and runs, just without program loading.
if(RUT_ENABLE_JIT)
    target_sources(rut PRIVATE serve_loader.cc)
    target_link_libraries(rut rut_jit)
    target_compile_definitions(rut PRIVATE RUT_ENABLE_JIT=1)
endif()
