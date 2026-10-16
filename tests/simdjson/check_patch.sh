#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
source_dir="$root/third_party/simdjson"
expected=9c003534b1be3bc4f1322bfa7a770a7ffbf247d9
[[ $(git -C "$source_dir" rev-parse HEAD) == "$expected" ]]
probe_dir=$(mktemp -d /tmp/rut-simdjson-patch.XXXXXX)
trap 'rm -rf "$probe_dir"' EXIT
git -C "$source_dir" archive "$expected" | tar -x -C "$probe_dir"
cd "$probe_dir"
git apply --check "$root/patches/simdjson/0001-ondemand-allocator-hooks.patch"
git apply "$root/patches/simdjson/0001-ondemand-allocator-hooks.patch"
for development_checks in 0 1; do
  "${CXX:-clang++}" -std=c++23 -O2 -fno-exceptions -fno-rtti \
    -fno-threadsafe-statics -DSIMDJSON_EXCEPTIONS=0 \
    -DSIMDJSON_THREADS_ENABLED=0 -DSIMDJSON_RUT_ALLOCATOR=1 \
    -DSIMDJSON_DEVELOPMENT_CHECKS="$development_checks" \
    -ffunction-sections -fdata-sections -I include -I src \
    "$root/tests/simdjson/allocator_probe.cc" src/simdjson.cpp \
    -Wl,--gc-sections -nostdlib++ -o probe
  ./probe
  if readelf -d probe | rg -q 'NEEDED.*(libstdc\+\+|libc\+\+)'; then
    echo 'FAIL: C++ standard library dependency' >&2
    exit 1
  fi
  echo 'PASS: no libstdc++ / libc++ ELF dependency'
done
