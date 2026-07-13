#!/bin/bash
# dev.sh — build, test, lint, format for the Rue project.
#
# Usage:
#   ./dev.sh              # build + test
#   ./dev.sh build        # build only
#   ./dev.sh test         # build + run tests
#   ./dev.sh tidy         # run clang-tidy on source files
#   ./dev.sh format       # run clang-format (check mode)
#   ./dev.sh format-fix   # run clang-format (in-place)
#   ./dev.sh all          # build + test + tidy + format-check
#   ./dev.sh clean        # remove build directory

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$PROJECT_DIR/build"
SRC_FILES=$(find "$PROJECT_DIR/include" "$PROJECT_DIR/src" "$PROJECT_DIR/tests" \
    "$PROJECT_DIR/testing" "$PROJECT_DIR/bench" \
    -name '*.h' -o -name '*.cc' 2>/dev/null | grep -v third_party)

# ---- Configure (if needed) ----
configure() {
    if [ ! -f "$BUILD_DIR/build.ninja" ]; then
        echo "=== Configuring (clang, Ninja) ==="
        cmake -B "$BUILD_DIR" -G Ninja \
            -DCMAKE_C_COMPILER=clang \
            -DCMAKE_CXX_COMPILER=clang++ \
            "$PROJECT_DIR"
    fi
}

# ---- Build ----
build() {
    configure
    echo "=== Building ==="
    ninja -C "$BUILD_DIR"
}

# ---- Test ----
test() {
    build
    echo "=== Running all tests ==="
    ninja -C "$BUILD_DIR" check
}

# ---- Coverage ----
coverage() {
    echo "=== Building with coverage ==="
    cmake -B "$BUILD_DIR-cov" -G Ninja \
        -DCMAKE_C_COMPILER=clang \
        -DCMAKE_CXX_COMPILER=clang++ \
        -DCMAKE_CXX_FLAGS="-fprofile-instr-generate -fcoverage-mapping" \
        -DCMAKE_BUILD_TYPE=Debug \
        "$PROJECT_DIR"
    ninja -C "$BUILD_DIR-cov"

    echo "=== Running tests with profiling ==="
    LLVM_PROFILE_FILE="$BUILD_DIR-cov/test_network.profraw" "$BUILD_DIR-cov/tests/test_network"
    LLVM_PROFILE_FILE="$BUILD_DIR-cov/test_integration.profraw" "$BUILD_DIR-cov/tests/test_integration"
    LLVM_PROFILE_FILE="$BUILD_DIR-cov/test_arena.profraw" "$BUILD_DIR-cov/tests/test_arena"
    LLVM_PROFILE_FILE="$BUILD_DIR-cov/test_expected.profraw" "$BUILD_DIR-cov/tests/test_expected"
    LLVM_PROFILE_FILE="$BUILD_DIR-cov/test_http_parser.profraw" "$BUILD_DIR-cov/tests/test_http_parser"
    LLVM_PROFILE_FILE="$BUILD_DIR-cov/test_buffer.profraw" "$BUILD_DIR-cov/tests/test_buffer"

    echo "=== Coverage report ==="
    llvm-profdata merge "$BUILD_DIR-cov"/*.profraw -o "$BUILD_DIR-cov/merged.profdata"
    llvm-cov report \
        --instr-profile="$BUILD_DIR-cov/merged.profdata" \
        --object "$BUILD_DIR-cov/tests/test_network" \
        --object "$BUILD_DIR-cov/tests/test_integration" \
        --object "$BUILD_DIR-cov/tests/test_arena" \
        --object "$BUILD_DIR-cov/tests/test_http_parser" \
        --object "$BUILD_DIR-cov/tests/test_expected" \
        --object "$BUILD_DIR-cov/tests/test_buffer" \
        --sources include/rut/ src/
}

# ---- clang-tidy ----
tidy() {
    configure
    echo "=== Running clang-tidy ==="
    # Exclude all arch-specific SIMD backends — they require target intrinsic
    # headers that may not be available on the host (e.g. sse2.cc on ARM).
    # Only lint the scalar backend and the main parser code.
    local src_cc=$(find "$PROJECT_DIR/src" -name '*.cc' \
        ! -path '*/simd/sse2.cc' \
        ! -path '*/simd/avx2.cc' \
        ! -path '*/simd/avx512.cc' \
        ! -path '*/simd/neon.cc' \
        ! -path '*/simd/sve.cc' | \
        grep -v third_party)
    # Match CI exactly (ci.yml): bugprone-*/performance-* are hard errors and
    # the exit code must gate `./dev.sh all` — the old grep-only form let
    # CI-fatal findings pass silently on developer machines.
    if clang-tidy -p "$BUILD_DIR" --warnings-as-errors='bugprone-*,performance-*' \
        $src_cc 2>&1 | tee /tmp/rut-tidy.log | grep -E "error:"; then
        echo "clang-tidy FAILED (errors above; full log: /tmp/rut-tidy.log)"
        return 1
    fi
    echo "No tidy errors (warnings, if any, are in /tmp/rut-tidy.log)."
}

# ---- clang-format (check) ----
format_check() {
    echo "=== Checking clang-format ==="
    local bad=0
    for f in $SRC_FILES; do
        if ! clang-format --dry-run --Werror "$f" 2>/dev/null; then
            echo "  needs formatting: $f"
            bad=1
        fi
    done
    if [ $bad -eq 0 ]; then
        echo "All files formatted correctly."
    else
        echo "Run './dev.sh format-fix' to auto-format."
        return 1
    fi
}

# ---- clang-format (fix) ----
format_fix() {
    echo "=== Formatting with clang-format ==="
    echo "$SRC_FILES" | xargs clang-format -i
    echo "Done."
}

# ---- Clean ----
clean() {
    echo "=== Cleaning build directory ==="
    rm -rf "$BUILD_DIR"
    echo "Done."
}

# ---- All ----
all() {
    build
    test
    tidy
    format_check
}

# ---- Main ----
case "${1:-test}" in
    build)       build ;;
    test)        test ;;
    tidy)        tidy ;;
    format)      format_check ;;
    format-fix)  format_fix ;;
    coverage)    coverage ;;
    clean)       clean ;;
    all)         all ;;
    *)
        echo "Usage: $0 {build|test|tidy|format|format-fix|coverage|clean|all}"
        exit 1
        ;;
esac
