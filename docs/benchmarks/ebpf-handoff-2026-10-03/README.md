# Atomic eBPF body handoff — 2026-10-03

**Status:** real kernel bytecode loading and byte-correct isolated TCP transfers
work. The current mechanism trades lower process CPU for substantially longer
transfer time. It is not enabled in Rut's serving loops, and these results do not
establish a Rut throughput gain or maximum hardware utilization.

## Mechanism validated

`bench_ebpf_handoff` permanently enrolls the upstream response socket before the
request can cause a response. The downstream socket is a redirect target only.
Headers are parsed and rewritten in userspace. An atomic ownership/counter CAS
admits body redirection only after every previously passed byte has been sent.
Whole packets within Content-Length redirect; a crossing packet passes intact
and its body prefix is sent in userspace after a TCP sequence ordering barrier.
Successor bytes remain readable only on the source socket.

The compiler exports the same direct bytecode tested by the loader: packet
verdict 164 instructions / 1312 bytes, control 31 instructions / 248 bytes.
The private artifact ABI is 3 and eBPF plan version is 2. Loader validation
rejects modified instructions, map FD values and incorrect file sizes.

Four unrolled CAS attempts bound verifier work. Completion/failure events carry
socket cookie, connection ID and generation through a shard-owned ring buffer.
Overflow marks the flow failed; notification capacity does not guarantee delivery
when connection slots are retired/reused before consuming their old events.
A production integration must independently detect missing completion events.
Notification/budget completion also does not prove TCP output-backlog drain.

## Correctness evidence

[kernel-suite.jsonl](kernel-suite.jsonl) contains 243 successful records:

- 240 transfers: sizes 1, 4095, 4096, 4097, 65537 and 1048576 bytes; prequeue
  0 or min(size, 4096); producer delay 0 or 10 ms; reader delay 0 or 100 ms;
  five repetitions per combination. Every transfer coalesces the final body
  chunk with an 18-byte successor in one send and immediately half-closes.
- Atomic control/rollback self-test: stale CAS cannot commit, duplicate socket
  enrollment preserves existing entries, intermediate enrollment failure removes
  only entries created by that attempt, and failed state cannot be rearmed.
- Notification self-test: 170 queued records retain cookie and generation while
  slot 7 is reused; subsequent ring overflow is visible in flow state. Draining
  yields the expected FIFO events with no duplicate tail event. Removing the
  redirect target emits a failure event for the correct cookie/generation.
- A real `.rut` program's exported packet verdict/control files load and transfer
  1 MiB with header rewrite, pending body bytes, slow reader, successor and FIN.
  See [compiled-plan.json](compiled-plan.json).

The fixture validates each body byte against an offset-dependent pattern,
copied+redirected+spliced byte accounting, rewritten headers, source-only
successor, both half-closes and map retirement. Copy/splice/auto fallback tests,
explicit required-capability failure, malformed export files and compiler-pipe
corruption tests are registered with CTest.

[ctest.log](ctest.log): eight related tests passed, including the existing native
loader/protocol and harness tests. [off-ctest.log](off-ctest.log): the OFF build
and three compiler/artifact tests passed. New emitter, loader and fixture pass
focused clang-tidy; the fixture documents suppression of include-cleaner's
glibc-private-header suggestions while retaining public POSIX headers. Existing
unrelated headers still emit suppressed warnings. This is not a full-repository
tidy or full test-suite pass.

## Performance evidence

Linux 6.19.10-300.fc44.x86_64, existing `nginx:latest` image used only as a
container environment, with all capabilities dropped except BPF and NET_ADMIN.
SELinux label separation is disabled for this disposable container; default
seccomp is retained. No privileged container, host security-policy change, new
dependency or system OpenSSL is used. The tests share one container network
namespace; TCP endpoints use loopback rather than physical NICs.

[three-way.jsonl](three-way.jsonl) has 108 samples: three body sizes, six cycles
of **copy, splice, eBPF, eBPF, splice, copy**. Each mode has 12 samples per size;
all samples, including eBPF candidates that finish entirely through copy, are
included. Prequeue and producer/reader delays are zero; successor is coalesced.
The final run was performed after the builds and other checks completed.

| Body | Mode | Process CPU median (ms) | Transfer time median (ms) |
|---|---|---:|---:|
| 64 KiB | copy | 0.372 | 0.203 |
| 64 KiB | splice | 0.389 | 0.207 |
| 64 KiB | eBPF | 0.422 | 0.230 |
| 1 MiB | copy | 3.640 | 1.548 |
| 1 MiB | splice | 3.572 | 1.570 |
| 1 MiB | eBPF | 3.242 | 2.453 |
| 16 MiB | copy | 52.507 | 21.710 |
| 16 MiB | splice | 51.181 | 21.727 |
| 16 MiB | eBPF | 47.844 | 38.659 |

Relative to copy, eBPF process CPU changes by +13.6%, -10.9%, -8.9%, while
transfer time changes by +13.1%, +58.5%, +78.1%. The median offload fractions
are 0%, 79.5%, 98.2%. Small responses often reach userspace before ownership
can commit. Replacing state polling with ring notifications did not remove the
transfer-time regression. Splice in this fixture is approximately level with
copy; the earlier sidecar splice experiment used a different workload and must
not be substituted for this same-fixture control.

CPU is `RUSAGE_SELF` for the fixture process, including its producer and reader
threads. It includes per-flow enrollment, header/control work and map retirement,
but excludes cold program loading and socket creation. It does not account for
unbound kernel workers outside the process: reduced process CPU is not evidence
of reduced whole-machine CPU. Transfer time is one fixture transfer, not Rut
request latency, concurrent throughput, p99 or a production capacity estimate.
No live epoll/io_uring cancellation/resource-lifetime, keep-alive reuse, TLS,
HTTP/2, physical NIC or NUMA performance claim is made here.

## Reproduce

Build instructions and export protocol are in [../../ebpf.md](../../ebpf.md).
On a host allowing these BPF operations, run:

```bash
build/bench/bench_ebpf_handoff required --packet-verdict --control-selftest
build/bench/bench_ebpf_handoff required --packet-verdict --notification-selftest
for size in 65536 1048576 16777216; do
  for iteration in 1 2 3 4 5 6; do
    for mode in off splice required required splice off; do
      build/bench/bench_ebpf_handoff "$mode" --packet-verdict --coalesced-tail \
        --size "$size" --prequeue 0 --delay-us 0 --slow-reader-us 0 || exit
    done
  done
done
```

This run's frozen binary is
`/home/hurricane/private/code/rut-ebpf-20261003/handoff-v2`; it was invoked inside
the container through the previously staged libc loader with a read-only bind
mount. [manifest.json](manifest.json) records binary/source/evidence hashes;
[summary.json](summary.json) contains the exact median values.

Kernel reference protocols:
[sockmap/sockhash](https://kernel.org/doc/html/next/bpf/map_sockmap.html),
[BPF ring buffer](https://www.kernel.org/doc/html/latest/bpf/ringbuf.html),
[TCP_INFO/SIOCOUTQ implementation](https://github.com/torvalds/linux/blob/master/net/ipv4/tcp.c).
