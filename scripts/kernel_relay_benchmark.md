# Container copy / splice mechanism probe

This standalone Linux experiment compares the same raw TCP relay with recv/send
and splice pumps, or an explicitly selected copy/eBPF pair. It does not run Rut handlers, terminate TLS, or
change the existing nginx acceptance profile. The relay and pinned nginx origin
share a container network namespace; the host client enters a published port.

Build and verify with the existing toolchain:

```sh
ninja -C build bench_kernel_relay
ctest --test-dir build -R '^test_kernel_relay$' --output-on-failure
```

The runner reuses the nginx harness's deterministic exact-body, slow-reader,
successor, 100-request keepalive, and origin-reuse checks. Its body-size override
is local to this runner; the original `native-streaming` CLI retains its 256 KiB
contract. Both relay modes set TCP_NODELAY and use a maximum 64 KiB transfer.
Splice requires permission to create 64 KiB pipes; setup failures invalidate the
run rather than silently falling back to copy.

Requirements match the existing local nginx harness: a local Docker daemon with
the pinned image already present, wrk, taskset, distinct physical CPU cores, and
readable `/proc` process accounting. The probe requires no extra capability.
The image runs it as UID/GID 65532 with all capabilities dropped, no-new-privileges,
and default seccomp. The runner verifies these properties and the shared netns.
Post-load container accounting currently requires cgroup v2 `memory.stat`.

The host-built executable depends only on libc and its ELF loader. Supply matching
host library files as read-only mounts; no image packages are installed. On a
SELinux host, create experiment-owned copies of the probe, loader, and libc and
label only those copies and the new output directory as container_file_t. Never
relabel system libraries. Freeze the probe before timing and record its build
source and hashes; the runner records binary/library hashes and environment.

```sh
python3 scripts/kernel_relay_benchmark.py \
  --relay /path/to/frozen/bench_kernel_relay \
  --loader /path/to/copied/ld-linux-x86-64.so.2 \
  --libc /path/to/copied/libc.so.6 --wrk /path/to/wrk \
  --output /path/to/new-output --body-size 1048576 \
  --server-cpu 2 --origin-cpu 3 --client-cpus 4,5 \
  --concurrency 1 32 --warmup 2 --duration 8 --repeats 3 \
  --first-engine copy
```

Repeat into another new directory with `--first-engine splice`; the engine order
also alternates within each run. Bodies must be positive multiples of 4096 up to
1 MiB. The single-worker probe supports up to 256 benchmark connections. Keep
body size, CPU allocation, durations and libraries identical across both orders.

`results.json` records each sample, including separate relay user/system CPU,
origin CPU, RSS, latency and warmup/load errors. `status.json` must be complete and
valid. Preflight files establish full body integrity and actual origin reuse;
wrk timing does not compare every body. Per-frontend isolation and cleanup logs
prove deployment conditions and report setup/I/O counters. I/O errors at client
abort during cleanup are separate from timed wrk errors. RSS omits kernel memory;
post-load memory.stat is not a peak measurement and includes its exec reader.

The measured shared-netns result supports a kernel data-movement experiment,
not a production Rut speedup or a claim that per-request userspace dispatch is
eliminated. Read the [2026-10-03 record](../docs/benchmarks/kernel-relay-sidecar-2026-10-03/README.md)
for both-order results, failed smoke history and validation limits.

## Optional L4 eBPF comparison

`--include-ebpf` selects **copy/eBPF**, replacing the copy/splice pair. Both
engines then run as container UID/GID 0 with only BPF and NET_ADMIN capabilities,
no-new-privileges, default seccomp and `label=disable`. This is opt-in; the default
UID 65532 / no-capability copy/splice experiment is preserved. Do not combine
`--include-ebpf` with `--first-engine splice`. Root's pipe quota caused failures
in an attempted three-way experiment; failed samples were rejected instead of
changing host pipe limits or adding capabilities.

The `bench_kernel_relay ebpf FRONT_PORT ORIGIN_PORT` mode admits the **entire
upstream TCP stream** before forwarding its first request. One source SOCKHASH
has a direct packet-verdict program; a separate target SOCKHASH has no receive
programs. Socket-cookie state holds a 64-bit byte counter, avoiding the L7 body's
per-response takeover and budget limit. Client-to-origin traffic remains copied.
On source EOF, TCP output progress must cover accepted redirect bytes before
propagating FIN. Socket-map cleanup tolerates entries already removed by TCP
teardown. Enrollment failure after a peer disappears is recorded separately
from setup failure; there is no payload-copy fallback after kernel admission.

This mode does not implement HTTP routing, body boundaries, header rewrite or
Rut's compiler route proof. It cannot be substituted for a production L7 route.

```sh
python3 scripts/kernel_relay_benchmark.py \
  --relay /path/to/frozen/bench_kernel_relay \
  --loader /path/to/copied/loader --libc /path/to/copied/libc.so.6 \
  --wrk /path/to/wrk --output /path/to/new-output \
  --include-ebpf --first-engine copy --body-size 1048576 \
  --server-cpu 2 --origin-cpu 3 --client-cpus 4,5 \
  --concurrency 1 32 --warmup 1 --duration 5 --repeats 3
```

`--origin-affinity shared` additionally allows the origin on the union of the
server and origin CPU masks. It keeps the physical core budget unchanged and
changes their scheduling freedom; default `dedicated` retains the original
placement. This is a container-local placement experiment, not a host workqueue
or IRQ policy change.

Results include aggregate and per-CPU `/proc/stat` execution deltas. These account
for kernel workers omitted from relay process CPU, but also include endpoints,
Docker/client activity and unrelated host activity. Normalize by successful body
bytes before comparison; they do not exclusively attribute CPU to the relay.

The [follow-up results](../docs/benchmarks/ebpf-followup-2026-10-03/README.md)
cover phase timing, larger batches, 512 MiB streams, sidecar concurrency,
placement changes and actual Rut reference runs.
