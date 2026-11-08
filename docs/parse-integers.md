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
All rows measure the signed **64-bit** parser, including the i32-sized corpus.

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
    bench/bench_parse_integer.cc -o /var/tmp/bench_parse_integer
taskset -c 2 /var/tmp/bench_parse_integer
```

The same target is available as `bench_parse_integer` in CMake. Omit the x86 flag
when building on another architecture. The benchmark itself has only libc and
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
research measurements, not build dependencies. ARM and big-endian performance
have not been measured.

### Validation

Tests cover both signed boundaries, ASCII grammar, all four-digit values,
random inputs against an independent cutoff oracle, mutations through all 256
byte values, and spans ending immediately before a protected page. Compiler
coverage includes width inference, optional handling, type/arity errors, user
shadowing, pipes, and malformed RIR rejection. Runtime coverage exercises text
and Bytes through JIT/native HTTP and WebSocket paths, and HTTP integration at
optimization levels 0 and 2 for epoll and io_uring.
