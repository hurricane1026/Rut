# Consistent-hash validation

Implementation environment: Linux x86-64, Release build, Clang 22, pinned static
OpenSSL. The implementation adds no dependency or default-CI benchmark.

## Local results

| Check | Result |
| --- | --- |
| Complete frontend suite | 1318 tests, 23115 checks passed |
| Complete JIT suite | 650 tests, 59923 checks passed |
| Complete native-program suite | 91 tests, 5186 checks passed |
| Complete network suite | 1679 tests, 5280576 checks passed |
| Existing gRPC/WebSocket suite | 107 tests, 26457 checks passed |
| New concurrent gRPC affinity/accounting case | 1 test, 38 checks passed |
| Complete io_uring idle-trim suite | 30 tests, 6407 checks passed |
| Hash vectors and 100,000-key properties | 2 tests, 700021 checks passed |
| Live HTTP/1 and HTTP/2 independent oracle | Passed on epoll and io_uring |
| GCC/Clang determinism | Same 100,000-key selection checksum: `3431893258761746118` |
| Clang ASan/UBSan | Standalone 100,000-key algorithm probe passed |
| Scoped clang-tidy | Eight changed source files passed the CI bugprone/performance warning policy |
| Formatting and local documentation links | Passed |
| Runtime ELF dependencies | `libc.so.6` only; no C++ runtime or LLVM dependency |

The wire test covers byte-string and IPv4 keys, environment-provided seeds,
reordered endpoints, one/two shards, H1 downstream/upstream reuse, H2 stream
isolation on one connection, zero weights, and invalid keys before upstream I/O.
Network tests exercise retry exclusion, health fail-open, strict healthy capacity
and distinct old/new configuration snapshots. Native tests execute the compiled
handler after source removal. The JIT case also covers a timer yield and gRPC
invalid-key classification; network tests decode immediate and deferred trailers-only error responses.

Run the reproducible checks from the repository root after building their targets:

```bash
build/tests/test_frontend
build/tests/test_jit
build/src/test_native_program
build/tests/test_network
build/tests/test_grpc_proxy
build/tests/test_iouring_idle_trim
build/tests/test_hash --filter=consistent_hash
python3 tests/test_consistent_hash.py --server build/src/rut --backend epoll
python3 tests/test_consistent_hash.py --server build/src/rut --backend io_uring
python3 tests/test_consistent_hash.py --server build/src/rut --backend epoll --kong
```

The standalone portability probe compiled `consistent_hash.h` plus the existing
`hash.cc`/C digest library with both GCC and Clang. The Clang run enabled
`-fsanitize=address,undefined -fno-sanitize-recover=all`. It used 100,000
`tenant-N` keys, eight `127.0.0.(1+i):9000+i` endpoints and weights
`[65535,1,0,3,7,11,13,65534]`, folding selected indices with `sum = sum*33+index`
in unsigned 64-bit arithmetic. Its seed was the public fixture seed.

## Kong boundary

The optional comparison uses Kong OSS 3.9.1 at the immutable digest in
[pinned-kong-image.txt](../tests/pinned-kong-image.txt). Its configuration uses
`algorithm: consistent-hashing`, `hash_on: header`, `hash_on_header: key`, and
static IPv4 targets with weights 1, 3 and 0. Header affinity, weighted distribution,
zero-weight disablement and reorder stability passed for 500 deterministic keys.
After enabling the third target, one run observed 26/500 keys moving between old
targets. Counts depend on endpoint ports. The test records this difference instead
of requiring Kong to satisfy Rut's stricter HRW addition guarantee. The two
algorithms do not promise identical endpoint placement. This comparison does not
extend to other Kong versions or every hash-source/health configuration.

Kong's [upstream documentation](https://developer.konghq.com/gateway/entities/upstream/)
describes its Ketama principle and explicit hash-source configuration. The fixed
version execution above, rather than moving documentation, defines this test's
compatibility scope.

## Open validation boundaries

- ARM64 execution has not been run locally; GCC/Clang agreement here is x86-64.
- Production throughput, tail latency and large-scale reload/cancellation stress
  acceptance gates are not claimed complete. Benchmarks remain on demand.
- The ordinary H2-to-H1 proxy has one async slot. Its same-connection fixture
  closes upstream responses. With keep-alive origins, the io_uring fixture can
  return 502 on the next stream; the same failure reproduced with `.roundRobin`.
  This pre-existing policy-independent drain boundary is not fixed in this PR.
- Transparent WebSocket upgrades and CONNECT reject with 503 for this policy.
  Explicit connection waits keep their existing policy.
