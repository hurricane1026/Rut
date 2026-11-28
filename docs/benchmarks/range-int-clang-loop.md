# Clang code generation for the range_int accumulation loop

The bare-integer and `range_int` variants of `compare_accumulate` compute the same result. Clang 22.1.8 produced byte-identical machine code for this function on x86-64. The function occupied 164 bytes with `-O3` and 324 bytes with `-O3 -march=native`. The assembly regression compares 37 functions at `-O2` and `-O3` for x86-64 and AArch64, including construction from native integer types and a loop that accumulates only values in `[3, 100)`.

## Checked accumulation

The assembly gate also compares the output-pointer form with a bare-integer loop that filters for `[3, 100)`. A trial using `core::Expected` generated a different vector bounds check in Clang's default x86-64 `-O3` build. On the same host at 4,096 input elements, the trial took about 0.446 ns per element, compared with 0.383 ns for the output-pointer form. Reversing the link order produced the same relative difference. The checked conversions use the output-pointer form.

## Reproduce

Run on Linux with Clang 22 and GNU `objcopy`.

```bash
python3 scripts/check_range_int_codegen.py --compiler clang++-22 --show-asm
python3 scripts/check_range_int_codegen.py --compiler clang++-22 --target aarch64-linux-gnu
python3 scripts/bench_range_int_loop.py
python3 scripts/bench_range_int_loop.py --measure
```

The timing harness pins itself to the first CPU in its affinity mask, uses the same input for both functions, and alternates which one runs first within each of 41 pairs. It verifies the output, reverses the object-file link order, and repeats the test with both symbols bound to a single address as a timing control.

## Results

AMD Ryzen Threadripper 3990X, CPU 0, Clang 22.1.8 (Fedora 22.1.8-4.fc44). Values are median paired `range_int / raw` time ratios. A value above 100% means the `range_int` symbol took longer.

| Compiler flags | Input elements | Raw linked first | Wrapped linked first | Same address |
| --- | ---: | ---: | ---: | ---: |
| `-O3` | 16 | 89.14% | 99.49% | 100.00% |
| `-O3` | 4,096 | 112.30% | 89.25% | 99.87% |
| `-O3` | 262,144 | 112.13% | 89.01% | 100.00% |
| `-O3` | 4,194,304 | 104.99% | 94.88% | 100.04% |
| `-O3 -march=native` | 16 | 105.51% | 94.69% | 99.97% |
| `-O3 -march=native` | 4,096 | 100.30% | 99.49% | 100.05% |
| `-O3 -march=native` | 262,144 | 99.56% | 100.39% | 100.09% |
| `-O3 -march=native` | 4,194,304 | 99.99% | 99.47% | 99.72% |

With 4,096 elements at `-O3`, swapping the order of the two identical functions reversed the timing difference. The same-address control was within 0.13% at that size. This isolates the observed timing difference to code placement for this loop. The timings are a local measurement on this CPU and compiler.
