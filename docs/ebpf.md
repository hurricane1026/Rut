# Experimental eBPF compiler plans

Rut can analyze an existing `.rut` program and export eBPF body-transfer bytecode.
The compiler exports a validated atomic body-handoff primitive, exercised by an
isolated TCP probe: **business traffic still uses the existing userspace runtime**.
It does not implement `firewall {}`, XDP,
request routing in BPF, or kTLS integration.

Build on Linux with the existing LLVM/compiler toolchain:

```bash
cmake -S . -B build -DRUT_ENABLE_EBPF=ON
cmake --build build --target rut rut-compile
build/src/rut app.rut --ebpf-plan
build/src/rut app.rut --emit-ebpf /path/to/new/output-prefix
```

`RUT_ENABLE_EBPF` defaults to OFF and currently requires `RUT_ENABLE_JIT=ON`.
The serving process remains LLVM-free. No libbpf, system TLS library, external
BPF compiler, or new language keyword is added.

`--ebpf-plan` prints JSON and exits without starting listeners, publishing caches,
or opening access logs. `--emit-ebpf PREFIX` instead creates:

- `PREFIX.parser.bpf`: raw stream-parser instructions, 176 bytes;
- `PREFIX.verdict.bpf`: raw stream-verdict instructions, 248 bytes;
- `PREFIX.packet-verdict.bpf`: atomic SK_SKB packet verdict, 1312 bytes;
- `PREFIX.handoff-commit.bpf`: atomic ownership control program, 248 bytes;
- `PREFIX.json`: route decisions, required kernel capabilities and relocations.

The output directory must already exist. Existing files are never overwritten;
if a later output fails, files created by that export attempt are removed.
Export without any body candidate fails; `--ebpf-plan` still reports all reasons.
These diagnostic commands use source listener metadata; TLS/h2 CLI overrides are
rejected. Normal serving without either flag preserves the existing data path.

## What the compiler proves

The planner runs on verified, fully inlined RIR, before native artifact emission.
It conservatively admits a single-block terminal `RetForward` containing only
constant metadata. The upstream and optional header-policy IDs must be constant.
Fixed header policies can remain in userspace while the untouched body becomes
a candidate. Routing, upstream selection, header processing and errors remain
userspace responsibilities; a candidate is not a proof of whole-request bypass.

The first classifier rejects request-body access, regex, yields/buffered forward,
rate limits/throttling, policy bundles, unproved branches, other computations or
side effects, dynamic metadata, TLS listeners and terminate-mode WebSocket routes.
It inspects expanded middleware too. Conservative rejection can include programs
that future proofs could safely accelerate.

Every report contains `active_routes: 0` and `runtime_handoff: "unavailable"`.
No production `--ebpf=auto|required` activation flag is exposed yet. The earlier
mechanism probe's `off/auto/required` switches remain experimental probe options.

## Bytecode and artifact contract

The compiler writes per-route plans and a shared fixed-frame transfer program into
the existing same-build native artifact. The native artifact ABI is version 3
and the plan is version 2;
the build fingerprint includes the eBPF build setting. The LLVM-free loader checks
framing, plan version/counts, candidate metadata and exact instruction templates.
Corrupt instructions, candidate counts and live FD relocation values are rejected.
An OFF build cannot request a plan, and normal compilation does not carry one.

This is fixed-template lowering for a body-transfer primitive, not a general
RIR-to-BPF backend. Raw instruction encoding is native to the same build's ABI.
The files need a loader; they are not an ELF object for `bpftool prog load`.

The loader must create a two-entry sockmap and a two-entry u32 array of remaining
body bytes. Parser and verdict need separate relocations of front local port at
instruction 3 and budget-map FD at instruction 6. The verdict additionally needs
socket-map FD at instruction 22. All placeholders in the exported files are zero.
The entry keys are front socket 0 and upstream socket 1. Body budgets are supplied
at runtime, not compiled as a particular request's Content-Length.

Required UAPI capabilities: SK_SKB program type 14; STREAM_PARSER/STREAM_VERDICT
attach types 4/5; SOCKMAP/ARRAY map types 15/2; map lookup/redirect helpers 1/52.
Code handles 4 KiB logical body frames; after the budget expires it passes 1-byte
frames back to userspace. This prototype favors a verifiable boundary over a
performance claim. Packet storage length must not replace logical-frame length.

The original parser/verdict pair remains a diagnostic of the older mechanism;
it does **not** provide atomic takeover of an already active TCP flow. Do not
attach it to live business sockets as an ownership protocol.

## Atomic handoff experiment

The new `packet-verdict` and `handoff-commit` pair is a separate protocol:

- Enroll a fresh upstream socket in a source SOCKHASH **before** sending its
  request. The downstream target SOCKHASH has no receive programs.
- A HASH entry keyed by source socket cookie holds a 40-byte `HandoffState`.
  Packets initially pass to userspace and atomically increment a byte counter.
- Userspace finishes parsing/rewriting headers and sending all bytes it has
  received. A shard-private one-element command ARRAY and SOCKET_FILTER
  `BPF_PROG_TEST_RUN` execute a compare-and-exchange on ownership/counter/budget.
  Arrivals between observation and commit cause a retry, rather than lost bytes.
- Owned packets wholly inside the remaining Content-Length redirect through
  `sk_redirect_hash`. A packet crossing the body end passes intact to userspace;
  userspace sends only its valid body prefix and preserves successor bytes.
- A RINGBUF carries terminal/failure events with source cookie, connection ID
  and generation. One shard consumes notifications. Ring overflow sets a failed
  flag: live integration needs an independent timeout/failure scan; capacity
  alone cannot prevent overflow when retired slots are reused before draining.
- Budget zero and a notification do not prove target TX-backlog completion.
  Before forwarding a tail prefix, the probe checks the target's TCP sequence
  progress (ACKed bytes read before SIOCOUTQ), relative to a captured baseline.
  The peer reader proves final completion in this fixture.

No BPF C compiler or ELF stage is used. The compiler emits direct 8-byte
instructions, with four unrolled CAS attempts to bound verifier complexity.
Map FD relocations are reported in `handoff.relocations`; all exported values
are zero. Required attach type is SK_SKB_VERDICT (38), maps SOCKHASH/HASH/ARRAY/
RINGBUF (18/1/2/27), and helpers lookup/cookie/redirect/ring output (1/46/72/130).
The loader creates separate source and target maps, patches FDs and refuses
modified templates. This is a trusted same-build primitive, not arbitrary code
or a general HTTP parser in BPF. Its body limit is `0x3fffffff` bytes and passed
counter is 32-bit; it is tested on fresh sockets, not general keep-alive reuse.

Build and run the fixture:

```bash
cmake -S . -B build -DRUT_ENABLE_EBPF=ON -DRUT_BUILD_EBPF_PROBE=ON
cmake --build build --target rut rut-compile bench_ebpf_handoff
build/src/rut app.rut --emit-ebpf /path/to/new/output-prefix
build/bench/bench_ebpf_handoff required --packet-verdict \
  --handoff-prefix /path/to/new/output-prefix --coalesced-tail
build/bench/bench_ebpf_handoff auto --packet-verdict
build/bench/bench_ebpf_handoff splice --coalesced-tail
```

`required` fails explicitly without kernel support/permission; `auto` selects
copy if initialization fails before sockets are enrolled. After possible
ownership commit, errors fail the flow; they never restart userspace copying.
`splice` is a separate comparator within the same fixture. Export loading checks
exact file sizes and template bytes. These modes do not start the Rut server.

The [atomic handoff results](benchmarks/ebpf-handoff-2026-10-03/README.md) show
correct transfers and a CPU/latency tradeoff. The current loopback experiment
does not justify default activation or a Rut throughput improvement claim.

The [follow-up experiments](benchmarks/ebpf-followup-2026-10-03/README.md)
separate phase/relay/endpoint costs, test 16/64 KiB batches and 512 MiB streams,
compare a separate L4 sidecar prototype, and measure actual Rut reference runs.
That L4 prototype admits an entire TCP stream; it is not emitted by the L7 route
planner and must not be treated as proof of safe whole-request bypass.

## What remains before live activation

The [mechanism experiments](benchmarks/ebpf-capability-2026-10-03/README.md) found
that consuming a header and then attaching sockmap with residual queued body can
stall. FIONREAD-empty is only a snapshot and does not prove atomic handoff against
concurrent arrivals. Therefore this increment does not attach business sockets.

A live integration still needs integration of atomic takeover/return, existing-buffer ownership,
request-by-request keep-alive boundaries, backpressure, FIN/reset/close handling,
shard ownership and RCU retirement. Both I/O backends need compatible cancellation
and reclamation semantics. Full buffering, retries, chunked bodies, HTTP/2 and TLS
need separate proofs. kTLS and sockmap must be probed as separate capabilities.

See the [compiler integration evidence](benchmarks/ebpf-compiler-2026-10-03/README.md)
for validation and a real `.rut` export loaded by the kernel mechanism probe.
