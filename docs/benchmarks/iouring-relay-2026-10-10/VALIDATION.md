# Validation of the submitted checkpoint

- Rebuilt `rut`, `rut-compile` and `test_network` in Release with clang on Linux.
  The PR runtime/test source was checked byte-for-byte against that build's
  source tree. Pre-existing test compilation warnings remain.
- `ctest -R '^test_network$' --output-on-failure`: passed after the final changes.
- clang-format dry-run with warnings as errors: all six changed C++ files passed.
- clang-tidy 22 on the changed lines in main/backend and included headers: passed
  with bugprone/performance warnings treated as errors. The unfiltered check
  encounters existing `alloc_h2_impl` derived-method shadowing in both event
  loops and unchecked `atoi` in slice_pool. The two new widening diagnostics
  were corrected. CI uses clang-tidy 20; the entire unfiltered local check is
  not reported as passing.
- Python byte-compilation and both entry-point help commands: passed.
- Repository scanner end-to-end smoke: all 11 buffer configurations plus two
  selected nginx candidates and Rut completed, 14 valid measurement rows and
  zero client errors. Checked each saved effective nginx configuration against
  the requested buffering mode, buffer sizes and disabled temp-file writes.
- Repository mixed-load smoke: io_uring candidate, alternative 64KiB binary,
  epoll candidate, and nginx completed serially, four valid rows, successful
  small/large payload preflights and zero client errors. Explicit runtime
  backend selection was checked by the script.

Smoke runs used one second of warmup and one second of measurement; they validate
script wiring, not throughput claims. The longer measurements are preserved in
the experiment subdirectories. Full CI, sanitizers and macOS/kqueue have not
been run locally for this submission.
