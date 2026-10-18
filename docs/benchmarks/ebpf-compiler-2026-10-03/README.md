# Rut compiler → native artifact → eBPF validation (2026-10-03)

This increment integrates body-candidate analysis and direct bytecode emission
into the actual Rut compiler. It does **not** attach production Rut connections
to sockmap: reports contain `active_routes: 0` and
`runtime_handoff: "unavailable"`. See [the feature contract](../../ebpf.md).

## Results

- `RUT_ENABLE_EBPF=ON`: Rut, its compiler helper, native-program tests, harness
  and the existing mechanism probe build successfully.
- Seven focused CTests pass: `test_ebpf_compiler`, `test_native_program`,
  `test_native_protocol`, `test_serve_loader`, `test_harness`, `test_sockmap_probe`,
  `test_kernel_relay`.
- `RUT_ENABLE_EBPF=OFF`: Rut and its helper build; compiler diagnostics explicitly
  reject requests for eBPF plans. The compiler, native-program and native-protocol
  CTests pass. Enabling eBPF with JIT disabled is rejected during configuration.
- The source test covers plain forward, a fixed request-header policy, local
  response, body inspection, regex, rate limiting, cache mutation, expanded
  middleware control flow and buffered policy bundles. Only the first two are
  candidates. This conservative classification is intentional.
- The real compiler pipe rejects corrupt map-FD placeholders and unexpected or
  missing plans. Native-program tests also reject invalid upstream/request-policy
  metadata and candidate counts; owned plans survive compiler exit/source removal.
- Export tests exercise filenames with spaces, existing-file preservation,
  partial-output cleanup, zero-candidate rejection and diagnostic argument errors.
- Changed C++ files pass format checks. The two new implementation files pass
  clang-tidy with warnings treated as errors and a header filter restricted to
  the new plan/bytecode headers. A broader scan of the integration files finds
  existing macro and multilevel-pointer diagnostics; it does not pass the whole
  file error gate. Those diagnostics are recorded in the local logs. No full
  repository test suite or production
  performance benchmark was run for this increment.

## Kernel execution of the actual compiler output

`example.rut` was compiled by `build/src/rut --emit-ebpf PREFIX`. The resulting
176-byte parser and 248-byte verdict match the prior bounded-body probe templates
byte for byte; map FDs and front-port relocations remain zero in the exported
files. The serving executable loads the plan from the native artifact emitted
by its sibling `rut-compile`; it does not link LLVM.

The exported files were supplied to the frozen mechanism probe from the
[previous capability experiment](../ebpf-capability-2026-10-03/README.md).
Container settings were `--cap-drop ALL --cap-add BPF --cap-add NET_ADMIN`,
`--security-opt label=disable`, and Docker's default seccomp profile. No
`--privileged`, SYS_ADMIN, image pull or host security-policy modification was
used. The existing `nginx:latest` image supplied a container environment only.

The [kernel result](kernel-bytecode.log) reports:

- bidirectional body transfer succeeds, `relay_userspace_bytes: 0`;
- rewritten headers remain in userspace, `header_userspace_bytes: 54`;
- a 17-byte successor returns to userspace at the body boundary;
- half-close checks pass.

The total verified payload is 2,097,169 bytes. Endpoints and loader are controlled
by the probe; these counters measure its relay path, not the entire process or
production Rut. The reported TLS errno fields are separate synthetic TX API
probes, not TLS traffic validation or kTLS/sockmap compatibility evidence.

## Reproduction

```bash
cmake -S . -B build -DRUT_ENABLE_EBPF=ON -DRUT_BUILD_EBPF_PROBE=ON
cmake --build build --target rut rut-compile bench_sockmap_probe bench_kernel_relay test_native_program test_serve_loader test_harness
ctest --test-dir build -R '^(test_native_program|test_native_protocol|test_serve_loader|test_ebpf_compiler|test_sockmap_probe|test_kernel_relay|test_harness)$' --output-on-failure
build/src/rut docs/benchmarks/ebpf-compiler-2026-10-03/example.rut --ebpf-plan
build/src/rut docs/benchmarks/ebpf-compiler-2026-10-03/example.rut --emit-ebpf /tmp/rut-body
```

The isolated probe consumes `/tmp/rut.body-parser.bpf` and
`/tmp/rut.body-verdict.bpf`, so copy the exported `.parser.bpf` and `.verdict.bpf`
files to those names before running:

```bash
build/bench/bench_sockmap_probe required --bytecode /tmp/rut --header-rewrite --bounded-body
```

This last command needs the kernel capabilities/security policy established by
the earlier matrix. On an unprivileged host it is expected to fail capability
loading. Container reproduction and the frozen loader layout are documented in
the previous experiment. `manifest.json` records hashes and the exact command
for this run; `plan.json` and bytecode hex dumps retain the compiler outputs.

The next live-runtime gate remains an atomic socket takeover/return protocol.
A queued-data check alone does not solve the race found in the previous probe.
