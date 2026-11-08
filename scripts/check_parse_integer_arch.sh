#!/usr/bin/env bash
# Compile every candidate, execute only when this CPU/OS supports its ISA.
# RUT_REQUIRE_AVX512=1 makes an absent AVX-512 execution a diagnostic failure.
set -euo pipefail
cd "$(dirname "$0")/.."
output=${1:-build/parse-integer-arch}
mkdir -p "$output"
compiler=${CXX:-clang++}
common=(-O3 -DNDEBUG -std=c++23 -fno-exceptions -fno-rtti -Wall -Wextra -Werror -Iinclude)
{
  uname -a
  "$compiler" --version
  if command -v lscpu >/dev/null; then lscpu; fi
} > "$output/environment.txt"
cat > "$output/cpu.cc" <<'CPP'
#include <string.h>
int main(int argc, char** argv) {
    if (argc != 2) return 1;
    if (!strcmp(argv[1], "portable")) return 0;
#if defined(__x86_64__)
    __builtin_cpu_init();
    if (!strcmp(argv[1], "sse2")) return !__builtin_cpu_supports("sse2");
    if (!strcmp(argv[1], "avx2"))
        return !(__builtin_cpu_supports("avx2") && __builtin_cpu_supports("ssse3"));
    if (!strcmp(argv[1], "avx512"))
        return !(__builtin_cpu_supports("avx512f") && __builtin_cpu_supports("avx512bw"));
#elif defined(__aarch64__)
    if (!strcmp(argv[1], "neon")) return 0;
#endif
    return 1;
}
CPP
"$compiler" "${common[@]}" "$output/cpu.cc" -o "$output/cpu"
# The benchmark and oracle always use baseline compiler flags. Only the parser
# object receives ISA flags, so auto-vectorization cannot contaminate baselines.
"$compiler" "${common[@]}" -Itesting -c tests/test_parse_integer.cc -o "$output/test.o"
"$compiler" "${common[@]}" -c bench/bench_parse_integer.cc -o "$output/bench.o"
case $(uname -m) in
  x86_64) arches=(portable sse2 avx2 avx512) ;;
  aarch64|arm64) arches=(portable neon) ;;
  *) arches=(portable) ;;
esac
link=()
if [[ $(uname -s) == Linux ]]; then link=(-Wl,--as-needed); fi
pin=()
if command -v taskset >/dev/null && [[ -r /proc/self/status ]]; then
  cpu=$(awk '/^Cpus_allowed_list:/ { split($2, parts, /[,-]/); print parts[1] }' /proc/self/status)
  pin=(taskset -c "$cpu")
fi
printf '| Architecture | Build | Execution |\n| --- | --- | --- |\n' > "$output/summary.md"
ran_avx512=0
for arch in "${arches[@]}"; do
  flags=()
  case $arch in
    sse2) flags=(-DRUT_INTEGER_ARCH_SSE2=1 -msse2) ;;
    avx2) flags=(-DRUT_INTEGER_ARCH_AVX2=1 -mavx2) ;;
    avx512) flags=(-DRUT_INTEGER_ARCH_AVX512=1 -mavx512f -mavx512bw) ;;
    neon) flags=(-DRUT_INTEGER_ARCH_NEON=1) ;;
  esac
  "$compiler" "${common[@]}" "${flags[@]}" -c src/runtime/parse_integer.cc -o "$output/$arch.o"
  "$compiler" "$output/test.o" "$output/$arch.o" "${link[@]}" -o "$output/test-$arch"
  "$compiler" "$output/bench.o" "$output/$arch.o" "${link[@]}" -o "$output/bench-$arch"
  if ! "$output/cpu" "$arch"; then
    echo "::notice::$arch compiled; execution skipped: CPU/OS lacks the required ISA"
    printf '| %s | passed | **not run: ISA unavailable** |\n' "$arch" >> "$output/summary.md"
    continue
  fi
  "${pin[@]}" "$output/test-$arch" | tee "$output/test-$arch.log"
  expected=$arch
  if [[ $arch == avx512 ]]; then expected=avx512bw; fi
  if ! grep -qx "Integer parser architecture: $expected" "$output/test-$arch.log"; then
    echo "::error::requested $arch kernel was not selected in the executable"
    exit 1
  fi
  "${pin[@]}" "$output/bench-$arch" | tee "$output/bench-$arch.csv"
  printf '| %s | passed | correctness and benchmark passed |\n' "$arch" >> "$output/summary.md"
  if [[ $arch == avx512 ]]; then ran_avx512=1; fi
done
printf '\n| Bits | Corpus | Selected architecture | ns/call |\n| --- | --- | --- | ---: |\n' >> "$output/summary.md"
for arch in "${arches[@]}"; do
  if [[ -f "$output/bench-$arch.csv" ]]; then
    awk -F, '$3 != "scalar_cutoff" && $3 != "portable_swar" { printf "| %s | %s | %s | %s |\n", $1, $2, $3, $4 }' \
      "$output/bench-$arch.csv" >> "$output/summary.md"
  fi
done
cat "$output/summary.md"
if [[ ${RUT_REQUIRE_AVX512:-0} == 1 && $ran_avx512 != 1 ]]; then
  echo '::error::AVX-512 execution was required but this runner does not expose F+BW'
  exit 1
fi
