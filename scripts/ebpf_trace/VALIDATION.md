# Functional validation

Validated on x86-64, Fedora kernel `6.19.10-300.fc44.x86_64`, with the
official bpftrace `v0.27.0` binary. These checks establish collection and
accounting behavior; they do not measure throughput gains or tracing overhead.

## Automated checks

`ctest --test-dir build-rel -R '^test_ebpf_trace_tools$' --output-on-failure`
passed: one registered CTest test containing eight unprivileged Python tests.
Coverage includes output decoding, failed attachment, event loss, warnings,
truncated output, exec, PID reuse, target exit, existing-output preservation,
argument validation, and SIGTERM cleanup of the collector's own tracer.

## Live relay

`smoke.py` passed with all five probe groups enabled. It checked 6,291,456
echoed bytes exactly, matched TCP byte totals on all four side/direction
combinations, matched successful receive-copy bytes on both sides, and
observed scheduler and fault events. Worker threads were created after attach.
The resulting status was `completed=true`, `usable=true`, without warnings.

## Rut io_uring

A single-shard Rut process using the io_uring backend proxied 24 raw HTTP
requests to a local nginx origin during an eight-second diagnostic trace.
All 24 response bodies matched the expected 1 MiB payload exactly:
25,165,824 body bytes total. Upstream TCP receive and downstream TCP send
each reported 25,169,376 bytes, including HTTP response headers.

TCP, receive-copy, scheduler, minor-fault and kernel-stack maps were present.
The resulting status was `completed=true`, `usable=true`, without warnings.
The target process identity remained unchanged throughout collection.

The tracer ran in a temporary container with the host PID namespace and
read-only BTF/tracefs mounts. Capabilities were limited to BPF, PERFMON,
SYS_RESOURCE and (for stack symbol resolution) SYSLOG. The container used
unconfined seccomp and disabled container labeling; no host sysctl or huge-page
configuration was changed. This is a validation setup, not a deployment recipe.

Raw local artifacts, retained outside the repository:

- `/tmp/rut-bounded-followup-20260928/ebpf-smoke-final/`
- `/tmp/rut-bounded-followup-20260928/ebpf-rut-smoke-r2/`

Kernel probe availability varies. Run `--check` on another host before
collecting measurements, and review the interpretation limits in the README.
