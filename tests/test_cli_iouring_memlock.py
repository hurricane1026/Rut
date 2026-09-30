#!/usr/bin/env python3
"""With RLIMIT_MEMLOCK below one io_uring ring's charge, startup must still
fail (exit 1, no fallback) and explain the locked-memory limit; with TLS the
existing epoll fallback must still happen and the diagnostic must say so.

Skips (exit 77) when the limit cannot take effect: CAP_IPC_LOCK held (root or
a privileged container), io_uring unavailable, the one-entry startup probe
already failing because other processes of this user hold locked memory, or a
kernel that does not charge rings to RLIMIT_MEMLOCK."""

import os
import resource
import select
import signal
import subprocess
import sys
import time

SKIP = 77
# The kernel charges whole host pages, so the limit and the expected charge
# both scale with the page size (4 KiB on x86-64; 16/64 KiB on some arm64/ppc64).
PAGE = resource.getpagesize()
# 16 pages: enough for the one-entry startup probe (2 pages), far below one shard.
LIMIT_BYTES = 16 * PAGE


def round_up_page(n):
    return (n + PAGE - 1) // PAGE * PAGE


# Ring sizes at the default --max-connections-per-shard (16384): SQ 1024 and
# CQ = 2 x capacity = 32768 (io_uring_ring_sizes() in
# include/rut/runtime/io_uring_memlock.h), with 2048 + 1024 provided-buffer
# entries. Per-shard charge: 632 KiB on 4 KiB pages. Keep in sync with
# io_uring_shard_locked_bytes() (unit-tested there against measured kernel
# values); update when ring sizes change.
SQ_ENTRIES = 1024
CQ_ENTRIES = 32768
CAPACITY = 16384
PER_SHARD_KIB = (
    round_up_page(SQ_ENTRIES * 64)
    + round_up_page(320 + CQ_ENTRIES * 16 + SQ_ENTRIES * 4)
    + round_up_page(2048 * 16)
    + round_up_page(1024 * 16)
) // 1024
REQUIRED_PER_SHARD_KIB = (
    round_up_page(SQ_ENTRIES * 64)
    + round_up_page(320 + CQ_ENTRIES * 16 + SQ_ENTRIES * 4)
    + round_up_page(2048 * 16)
) // 1024
FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def has_cap_ipc_lock():
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("CapEff:"):
                    return bool((int(line.split()[1], 16) >> 14) & 1)
    except OSError:
        pass
    return False


def skip(reason):
    print(f"SKIP: {reason}")
    sys.exit(SKIP)


def run_limited(binary, extra_args, stop_markers, limit):
    """Run rut under a lowered soft RLIMIT_MEMLOCK. Returns (output, returncode);
    returncode is None when the process was still running at a stop marker (it
    is then terminated). Output is stdout+stderr."""
    _, hard = resource.getrlimit(resource.RLIMIT_MEMLOCK)

    def lower():
        resource.setrlimit(resource.RLIMIT_MEMLOCK, (limit, hard))

    process = subprocess.Popen(
        [binary, "0", "--shards", "2", "--no-pin", "--drain", "0"] + extra_args,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        preexec_fn=lower,
        start_new_session=True,
    )
    output = bytearray()
    deadline = time.monotonic() + 10
    rc = None
    try:
        while time.monotonic() < deadline:
            ready, _, _ = select.select([process.stdout], [], [], 0.1)
            if ready:
                chunk = os.read(process.stdout.fileno(), 65536)
                if not chunk:
                    rc = process.wait(timeout=5)
                    break
                output.extend(chunk)
                text = output.decode(errors="replace")
                if any(m in text for m in stop_markers):
                    break
            elif process.poll() is not None:
                rc = process.returncode
                break
        else:
            raise AssertionError(f"timed out: {bytes(output)!r}")
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=3)
        process.stdout.close()
    return output.decode(errors="replace"), rc


def require(output, needles):
    for needle in needles:
        if needle not in output:
            raise AssertionError(f"diagnostic lacks {needle!r}: {output!r}")


def limits():
    _, hard = resource.getrlimit(resource.RLIMIT_MEMLOCK)
    limit = LIMIT_BYTES
    if hard != resource.RLIM_INFINITY and hard < limit:
        limit = hard
    return limit, hard


def common_needles(limit, hard):
    total = PER_SHARD_KIB * 2
    required_total = REQUIRED_PER_SHARD_KIB * 2 + (PER_SHARD_KIB - REQUIRED_PER_SHARD_KIB)
    needles = [
        "RLIMIT_MEMLOCK",
        f"soft {limit // 1024} KiB",
        f"at least {required_total} KiB for 2 shard(s) to start ({REQUIRED_PER_SHARD_KIB} KiB per "
        f"shard), {total} KiB ({PER_SHARD_KIB} KiB per shard: "
        f"SQ {SQ_ENTRIES} / CQ {CQ_ENTRIES} entries for --max-connections-per-shard {CAPACITY})",
        "plus whatever this user's other io_uring processes hold",
        "0 shard(s) initialised before it",
        f"ulimit -l {total} (KiB",
        f"LimitMEMLOCK={total}K",
        f"--ulimit memlock={total * 1024}",
        "CAP_IPC_LOCK",
        "--shards N",
        "smaller --max-connections-per-shard",
    ]
    if hard == resource.RLIM_INFINITY or hard > limit:
        needles.append("soft limit can be raised up to the hard limit")
    return needles


def case_plain(binary):
    limit, hard = limits()
    output, rc = run_limited(binary, [], ["Backend: epoll", "Listening on port "], limit)
    if "Backend: io_uring" not in output:
        skip("io_uring unavailable under the lowered limit (locked memory held elsewhere)")
    if rc is None or rc == 0:
        skip("server started despite a tiny RLIMIT_MEMLOCK; rings are not charged to it")
    if "Failed to init shard 0 (errno=12, source=2)" not in output:
        raise AssertionError(f"expected ENOMEM at shard 0: {output!r}")
    if rc != 1:
        raise AssertionError(f"exit code {rc}, expected 1: {output!r}")
    if "epoll" in output:
        raise AssertionError(f"unexpected backend fallback: {output!r}")
    if "falling back" in output:
        raise AssertionError(f"plain HTTP diagnostic mentions a fallback: {output!r}")
    require(output, common_needles(limit, hard) + ["remedies:"])


def case_tls(binary):
    limit, hard = limits()
    cert = os.path.join(FIXTURES, "localhost_cert.pem")
    key = os.path.join(FIXTURES, "localhost_key.pem")
    if not (os.path.exists(cert) and os.path.exists(key)):
        print("TLS case: fixtures missing, not run")
        return
    output, rc = run_limited(
        binary,
        ["--tls-cert", cert, "--tls-key", key],
        ["Listening on port "],
        limit,
    )
    if "Backend: io_uring (TLS)" not in output:
        skip("io_uring unavailable under the lowered limit (locked memory held elsewhere)")
    if "Failed to init shard 0 (errno=12, source=2)" not in output:
        skip("TLS server started on io_uring despite a tiny RLIMIT_MEMLOCK")
    require(
        output,
        common_needles(limit, hard)
        + [
            "  falling back to epoll (TLS); to keep io_uring:",
            "Backend: io_uring TLS startup failed; falling back to epoll (TLS)",
            "Listening on port ",
        ],
    )
    if "remedies:" in output:
        raise AssertionError(f"TLS diagnostic presents remedies as required: {output!r}")


def main():
    if len(sys.argv) != 2:
        print("usage: test_cli_iouring_memlock.py <rut-binary>", file=sys.stderr)
        return 2
    binary = sys.argv[1]
    if has_cap_ipc_lock():
        skip("CAP_IPC_LOCK held; RLIMIT_MEMLOCK does not apply")
    case_plain(binary)
    case_tls(binary)
    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
