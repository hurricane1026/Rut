# Strict decimal integer parsing

`parseInt(value) -> i32?` and `parseInt64(value) -> i64?` accept an unwrapped
`str` or `Bytes`. No import is required. `parseInt64` produces an inferred `i64`;
it does not add source-level `i64` annotations.

| Input | `parseInt` | `parseInt64` |
| --- | --- | --- |
| `"+00042"` | `42` | `42` |
| `"-0"` | `0` | `0` |
| `"-2147483648"` | `-2147483648` | `-2147483648` |
| `"2147483648"` | `nil` | `2147483648` |
| `b"-9223372036854775808"` | `nil` | minimum signed 64-bit value |
| `"9223372036854775808"` | `nil` | `nil` |
| `""`, `"+"`, `"42x"`, `" 42"`, `"42\r\n"`, `b"4\x002"` | `nil` | `nil` |

The entire span must match ASCII `[+-]?[0-9]+`. There is no whitespace trimming,
locale, separator, radix prefix, floating-point syntax, saturation, wrapping or
partial consumption. Arbitrarily many leading zeros are accepted within the
input span's existing size limits. Callers must isolate a protocol field before
parsing it: a RESP line's trailing CRLF is not part of a decimal field.

Use optional binding, nil checks or `.or(...)` for failure. The operations are
pure: they do not allocate, perform I/O, retain the input, change `netError()`, or
need a request arena. They work in HTTP routes, helpers and WebSocket callbacks.
Ordinary user bindings shadow these builtin names. JIT and native artifacts use
the same small runtime helper; the native helper allowlist includes it explicitly.

## Research and selection — 2026-11-08

The recent [fast_float integer parser](https://github.com/fastfloat/fast_float/blob/78b6a96f28b9a7b66a4d95a34fb3ed9edbb73163/include/fast_float/ascii_number.h)
(file last changed 2026-10-29) and
[simdjson number parser](https://github.com/simdjson/simdjson/blob/db0a231baf41c6c2981b5ee3e8e08444e57973de/include/simdjson/generic/numberparsing.h)
(file last changed 2026-11-02) use length-sensitive parsing and packed digit
arithmetic. These exact revisions were inspected and compared. Their number
conversion techniques apply to this task; their surrounding APIs, JSON grammar
and padding assumptions do not define Rut's parsing contract.

The 2026 paper [Converting an Integer to a Decimal String in Under Two Nanoseconds](https://arxiv.org/abs/2604.26019)
studies **integer-to-string formatting**, including AVX-512 IFMA. It is relevant
to future formatting work, but does not supply a string-to-integer parser.

Rut uses a portable, dependency-free scalar/SWAR kernel:

1. Consume at most one sign and reject an empty remainder.
2. For fewer than eight bytes, validate and accumulate directly. These inputs
   cannot overflow either supported width, so no per-digit cutoff is needed.
3. For longer inputs, skip leading zeros (eight zeros at a time when possible),
   then reject more than ten significant digits for i32 or nineteen for i64.
4. Validate and combine eight-digit blocks, then four digits and a scalar tail.
   SWAR treats several digit lanes in an ordinary integer register; the
   multiply-and-mask reduction follows the established packed decimal technique
   used by the parsers above. No architecture-specific vector ISA is required.
5. Check the exact positive/negative limit once. Accumulation fits in u64 with
   at most nineteen digits; unsigned arithmetic forms negative result bits,
   including INT64_MIN, without signed overflow.

Every word load is guarded by the remaining span length and uses a fixed-size
`memcpy`, so unaligned input and a boundary directly before an unreadable page
are supported. Big-endian targets normalize loaded digit words. Input need not
be NUL-terminated or padded. The implementation does not call the generic JSON
helper or change the project's CPU baseline.

### Measurements

Host: Intel Core i7-10700, GCC 16, Linux x86-64, CPU 2 pinned with `taskset`.
Release microbenchmark flags: `-O3 -DNDEBUG -march=x86-64-v2 -std=c++23`.
Each corpus has 4,096 deterministic entries, 512 traversals per trial, five
trials; the table reports the best ns/call. Results are checked against an
independent per-digit cutoff parser before timing, and checksums are consumed.
The initial table below measures the signed **64-bit** portable kernel, including
the i32-sized corpus. The current benchmark emits separate 32-bit and 64-bit rows
and additionally compares the selected runtime architecture.

| Corpus | Per-digit cutoff | Rut kernel | Speedup |
| --- | ---: | ---: | ---: |
| 1–3 digits | 5.92 | 5.34 | 1.11× |
| i32-sized, 8–10 digits | 14.06 | 8.76 | 1.61× |
| i64-sized, 16–19 digits | 21.67 | 8.38 | 2.58× |
| Mixed 1–19 digits | 16.48 | 12.84 | 1.28× |
| Malformed/overflow | 10.15 | 7.70 | 1.32× |
| 8–127 bytes, leading zeros | 66.33 | 21.45 | 3.09× |

Reproduce from the repository root:

```bash
g++ -O3 -DNDEBUG -march=x86-64-v2 -std=c++23 -Iinclude \
    bench/bench_parse_integer.cc src/runtime/parse_integer.cc \
    -o /var/tmp/bench_parse_integer
taskset -c 2 /var/tmp/bench_parse_integer
```

The same target is available as `bench_parse_integer` in CMake. Its driver and
kernel are both optimized, including when the surrounding build tree is Debug.
Omit the x86 flag when building on another architecture. The benchmark itself has only libc and
project-header dependencies.

A separate candidate comparison on the same host included length-only scalar,
eight-digit SWAR, SSSE3, `std::from_chars`, and the pinned fast_float integer
parser, with wrappers matching Rut's optional plus sign and full consumption.
For 16–19 digits, measured times were approximately 8.3 ns for the final kernel,
11.4 ns for fast_float and 15.8 ns for `std::from_chars`. A raw SSSE3 candidate
was faster for long values (about 7.4 ns), but per-call feature dispatch lost its
advantage on mixed lengths; this CPU has no AVX-512. This supports the portable
kernel for the current workload and baseline. It is **not** a claim that SWAR
wins on every CPU, input distribution or batch size.

These are warm microbenchmarks including a non-inlined function call, not
end-to-end client or gateway throughput. The shipped benchmark reproduces the
baseline/kernel comparison; the optional external-library/ISA candidates are
research measurements, not build dependencies. The initial study did not measure ARM or big-endian performance; native arm64
measurements are now collected by the architecture CI job below.

### Validation

Tests cover both signed boundaries, ASCII grammar, all four-digit values,
random inputs against an independent cutoff oracle, mutations through all 256
byte values, and spans ending immediately before a protected page. Compiler
coverage includes width inference, optional handling, type/arity errors, user
shadowing, pipes, and malformed RIR rejection. Runtime coverage exercises text
and Bytes through JIT/native HTTP and WebSocket paths, and HTTP integration at
optimization levels 0 and 2 for epoll and io_uring.

## Architecture candidates and CI

The default remains `RUT_INTEGER_ARCH=portable` while collecting native results.
`RUT_INTEGER_ARCH` is independent of the HTTP scanner's `SIMD_ARCH`: choosing a
scanner ISA does not silently change numeric parsing. No per-call CPUID or
function-pointer dispatch is added. Only `rut_integer_parser` receives the
selected ISA compiler flags; the rest of the runtime keeps its baseline.

| `RUT_INTEGER_ARCH` | Required ISA | Digit reduction | Bounded loads |
| --- | --- | --- | --- |
| `portable` | ordinary integer operations | 8/4-digit SWAR | memcpy after length check |
| `sse2` | x86-64 SSE2 | widen bytes, paired multiply-add, pack, reduce 4-digit groups | exact 8/16 bytes |
| `avx2` | AVX2 target, including SSSE3 | VEX-encoded byte multiply-add, then word multiply-add | exact 8/16 bytes |
| `avx512` | AVX-512F + AVX-512BW | masked byte load/subtract/validation, paired multiply-add | byte mask selects exactly 8/16 bytes |
| `neon` | AArch64 Advanced SIMD | widening byte multiply and pairwise reductions | exact 8/16 bytes |

The shared parser handles signs, leading zeros, scalar tails and exact signed
limits. Vector candidates can reduce sixteen digits in one block; short inputs
still use the scalar path. AVX2 intentionally uses 128-bit VEX operations: one
signed i64 has at most nineteen significant digits, so a 32-byte load would need
padding or copying without adding useful digit lanes. AVX-512's byte masks allow
a fault-suppressing load without padding. VL, DQ, IFMA and VBMI are not required.
Instruction requirements follow the [Intel Intrinsics Guide](https://www.intel.com/content/www/us/en/docs/intrinsics-guide/index.html)
and [Arm NEON reference](https://arm-software.github.io/acle/neon_intrinsics/advsimd.html).

SVE/batch conversion remains a separate experiment: single i32/i64 fields fit
within sixteen digits plus a short tail, while SVE becomes more interesting
when validating or decoding multiple fields. No unmeasured SVE speedup is
claimed by the NEON candidate.

Select a runtime candidate with CMake, for example:

```bash
cmake -S . -B build-avx512 -DRUT_INTEGER_ARCH=avx512
cmake --build build-avx512 --target test_parse_integer bench_parse_integer
```

Run this binary only on hardware and an OS that enable F+BW. This is compile-time
selection, not a portable executable containing automatic ISA fallbacks.

For a lightweight native comparison without LLVM, TLS or other dependencies:

```bash
CXX=clang++ scripts/check_parse_integer_arch.sh /var/tmp/rut-integer-results
```

The script compiles all candidates for the host architecture. It always compiles
AVX-512 on x86, even when execution is unsupported. A separate baseline probe uses
CPU/OS-aware feature detection before launching ISA-specific executables. Only
the parser object receives ISA flags; the benchmark driver and independent
oracle are compiled once at baseline. Each executed candidate runs all strict
parser tests, including protected-page boundaries, followed by both i32 and i64
corpora. CSV columns are `bits,corpus,implementation,ns_per_call,checksum`.

CI's **Integer parser (x86)** and **Integer parser (arm64)** jobs run the script
natively on `ubuntu-24.04` and `ubuntu-24.04-arm`. Build and correctness failures
fail CI. Performance is informational until stable machine-specific baselines
exist. Artifacts contain CPU/compiler metadata, correctness logs, CSV timings
and an explicit per-ISA execution summary. An unavailable ISA is **not run**, not
a correctness pass. Standard hosted runner labels do not guarantee AVX-512, so
actual capability is probed on every run.

The `integer-parser` workflow-dispatch mode runs only these focused jobs.
Setting the `require_avx512` input makes the x86 diagnostic fail unless AVX-512
actually executes; the script equivalent is `RUT_REQUIRE_AVX512=1`. This allows a
hardware-specific validation request to distinguish a real run from a skip.

New sixteen-digit SSE2/AVX2 candidates passed local oracle and protected-page
tests. With Clang 22 on the i7-10700, initial 16–19-digit i64 runs measured about
8.0 ns for SSE2 and 7.6 ns for AVX2, against about 10 ns for the same run's inline
portable kernel. These are exploratory measurements from a different compiler
than the GCC table above; use the CI artifacts for comparisons on each runner.

### First native CI results

[Run 42462791552](https://github.com/hurricane1026/Rut/actions/runs/42462791552)
(commit `4574ea58c`, Clang 20.1.2) required actual AVX-512 execution. All x86
candidates and both ARM candidates passed, each with 596,009 oracle/bounds
checks. This includes the protected-page tests for AVX-512 masked loads and NEON
loads; neither architecture was emulated or skipped.

Selected-runtime times for **64-bit parsing**, ns/call:

| Native runner | Candidate | 1–3 digits | 8–10 digits | 16–19 digits | Mixed 1–19 digits |
| --- | --- | ---: | ---: | ---: | ---: |
| AMD EPYC 9V74 | portable | 4.87 | 5.66 | 7.42 | 6.97 |
| AMD EPYC 9V74 | SSE2 | 4.26 | 5.48 | 5.48 | 6.48 |
| AMD EPYC 9V74 | AVX2 | 4.26 | 5.51 | 5.35 | 6.46 |
| AMD EPYC 9V74 | AVX-512BW | 3.70 | 5.05 | 5.31 | 6.35 |
| Neoverse-N2 | portable | 5.43 | 8.09 | 9.41 | 11.03 |
| Neoverse-N2 | NEON | 5.54 | 8.67 | 8.35 | 10.72 |

The AVX2/AVX-512 long-value difference is under 1% in this run, so these results
do not establish a universal winner. NEON helps long values on this runner but
regresses some other corpora. Default selection stays portable pending broader
workload evidence. Do not compare x86 and ARM ns/call as an ISA-only effect:
these are different machines. Even short scalar-only paths vary with code
layout, compiler optimization and hosted-runner noise. Use the artifacts' full
32/64-bit CSVs and metadata rather than treating one best-of-five sample as a
stable regression threshold.
