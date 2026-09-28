# Opt-in eBPF tracing for Rut and nginx

This tool observes existing processes; it does not load a forwarding program,
change socket settings, or enable huge pages. Python uses only its standard
library. **bpftrace is an optional diagnostic dependency**, not a Rut build or
runtime dependency. No tool is downloaded or installed by these scripts.

## Requirements

- Linux 6.x+, kernel BTF (`/sys/kernel/btf/vmlinux`), tracing/perf support and
  bpftrace >= 0.25.0. Live validation used bpftrace 0.27.0 and Fedora kernel
  6.19.10 on x86-64; other kernels must pass `--check` first. Kernel function
  signatures and attachability are not a stable userspace API.
- Permission to load BPF and attach perf/tracing programs, and enough locked
  memory allowance. Typically run with root; suitably configured capabilities
  also work. Kernel lockdown/LSM policy can still deny access.
- Use **host process IDs (TGIDs)** in the same PID namespace as the tracer.
  Selecting a nginx master does not select its worker processes. Repeat `--pid`
  for every existing worker of interest. Rut's threads are included automatically.

The wrapper never escalates privileges or changes sysctls, mounts, security
policy, or resource limits. An executable wrapper can be supplied through
`--bpftrace`; it must forward arguments and signals and make `program.bt`
accessible at the same absolute path. Its stdout must contain only bpftrace
output. Container wrappers require the host PID namespace and access to kernel
BTF/tracefs; a normal benchmark container does not provide tracing permissions.

## Run

Start Rut or nginx normally, obtain its worker PID, then check attachability:

```sh
sudo python3 scripts/ebpf_trace/trace.py \
  --pid 12345 --check --output /tmp/rut-trace-check
```

Each invocation requires a **new output directory**. Inspect the generated
program without privileges or a bpftrace installation:

```sh
python3 scripts/ebpf_trace/trace.py --pid 12345 --emit
```

For a 15-second trace with the benchmark's default ports:

```sh
sudo python3 scripts/ebpf_trace/trace.py \
  --pid 12345 --duration 15 --front-port 8987 --origin-port 9987 \
  --output /tmp/rut-trace-01
```

Start the diagnostic load after `RUT_TRACE_READY` appears in `trace.jsonl`.
The interval is bounded by `--duration` after probe startup; compilation and
attachment add wall time. The target must remain alive until tracing finishes.
The collector does not launch or signal the target application. Ctrl-C stops
its own tracer, saves partial evidence and returns failure.

Extra detail, preferably in a separate diagnostic run:

```sh
sudo python3 scripts/ebpf_trace/trace.py \
  --pid 12345 --groups tcp sched fault rx-copy stacks --duration 15 \
  --output /tmp/rut-trace-detail-01
```

`--groups` replaces the default `tcp sched fault` selection. Unavailable
requested probes fail the run; they are never silently replaced with zero
counters. Use a smaller explicit selection if a kernel lacks an optional probe.

## What is measured

| Group | Probes | Measurements |
|---|---|---|
| `tcp` | fentry/fexit `tcp_recvmsg`, `tcp_sendmsg` | Entered/completed calls, requested/returned bytes, negative returns, zero returns, inclusive elapsed time and latency histogram |
| `sched` | raw `sched_switch`, `sched_wakeup`, `sched_wakeup_new` | Runnable queue delay and total off-CPU duration, separately, by TGID |
| `fault` | perf software minor/major faults, period 1 | Fault event counts in selected task contexts |
| `rx-copy` | fentry/fexit `skb_copy_datagram_iter` inside selected TCP receives | Copy-helper elapsed time and bytes for successful calls; automatically enables `tcp` |
| `stacks` | 99 Hz CPU profile with kernel stacks | Scheduled-task kernel stack samples; useful for identifying send-side copy paths |

The scheduler uses the Linux 6.x raw `sched_switch(preempt, prev, next,
prev_state)` signature. It timestamps both wakeups and runnable preemption;
sleeping switch-outs do not start runnable wait. Target threads created after
attachment are selected by their TGID. Intervals beginning before attachment
or ending after detach are incomplete and excluded from elapsed-time totals.

For TCP maps the key is `(TGID, direction, side)`:

- Direction: `1 = recv`, `2 = send`.
- Side: `1 = downstream` when the local port matches `--front-port`;
  `2 = upstream` when the peer port matches `--origin-port`; otherwise `0`.
- Local-port classification takes precedence. Ports are a coarse grouping,
  not a unique flow identity. Different IPs sharing a port are grouped together.
- Negative return values are recorded separately, including `-EAGAIN`;
  a zero return is **not universally EOF** (e.g. zero-length send/receive).

## Evidence and interpretation

- `program.bt`: exact generated program.
- `trace.jsonl`: raw bpftrace events, maps and histograms.
- `stderr.log`: tool diagnostics.
- `summary.json`: maps/histograms plus decoded `tcp` rows and mean elapsed time.
- `status.json`: kernel, tool version, arguments, source hash, target process
  identities, return code, completion and conservative `usable` flag.

Always check `status.json`. An attach failure, missing completion marker,
reported event loss, diagnostic warning, changed/exited target, or target exec
makes the measurement unusable. Process start times are compared before/after
to detect PID reuse; leader exit/exec also disables its selection in BPF.
An empty map means no events were observed, not proof that the cost is zero.
Map capacity and tool overhead still limit collection: bpftrace's map limits
apply, and the absence of a warning is not a proof of perfect event coverage.

**Elapsed time is not CPU time.** TCP functions can block or be descheduled.
Copy-helper time is nested within TCP time; runqueue time is contained in
off-CPU time. Do not add these overlapping totals. `rx-copy` measures the
receive-side skb helper, not a pure memcpy instruction or all sending copies.
Some kernels do not expose `_copy_to_iter/_copy_from_iter` as traceable function
entries; those probes are intentionally not required. Stack sampling includes
interruptions of userspace execution and is not a kernel-only cycle percentage.
Symbol names may be unavailable if kernel symbol access is restricted.

TCP bytes are successful function return bytes, not HTTP bodies, wire bytes,
unique stream bytes under MSG_PEEK, or completed application requests. Helper
errors may have performed partial copies that the success-byte counter omits.
The selected TGIDs do not account for all independent io_uring workers,
SQPOLL threads, IRQ/softirq work, or total host CPU consumption.

Tracing adds overhead, especially per-call copy probes and per-fault events.
Collect profiles separately from the nginx benchmark acceptance measurements.
Match body size, connection reuse, concurrency, CPUs and load duration when
comparing diagnostic traces. Check for other compiler/test workloads as well.
The tool reads socket metadata and stack addresses, **not application payloads**.

## Verification

See [validation results](VALIDATION.md) for live relay and Rut io_uring checks.

Unprivileged regression checks (including loss, partial output, process exit,
PID reuse, exec, failed attachment, SIGTERM cleanup and preservation of existing evidence):

```sh
python3 -m unittest discover -s scripts/ebpf_trace -p test_trace.py -v
```

Live, opt-in smoke test with real sockets and threads created after attachment:

```sh
sudo python3 scripts/ebpf_trace/smoke.py --output /tmp/ebpf-smoke-01
```

It checks 6 MiB of exact echo data through a local relay, verifies TCP byte
totals for both directions and both sides, verifies receive-copy bytes, and
requires fault/scheduler observations. This is functional verification, not a
throughput or overhead benchmark. It only stops its own fixture and tracer.

References: [bpftrace language](https://bpftrace.org/docs/release_025/language),
[CLI and JSON output](https://bpftrace.org/docs/release_025/cli),
[standard library](https://bpftrace.org/docs/release_025/stdlib).
