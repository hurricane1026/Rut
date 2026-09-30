#!/usr/bin/env python3
"""With RLIMIT_MEMLOCK below one io_uring ring's charge, startup must still
fail (exit 1, no fallback) and explain the locked-memory limit.

Skips (exit 77) when the limit cannot take effect: CAP_IPC_LOCK held (root or
a privileged container), io_uring unavailable, or a kernel that does not
charge rings to RLIMIT_MEMLOCK."""

import resource
import subprocess
import sys

SKIP = 77
LIMIT_KIB = 64
# Per-shard charge for the current ring constants (see io_uring_memlock.h).
PER_SHARD_KIB = 1652


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


def main():
    if len(sys.argv) != 2:
        print("usage: test_cli_iouring_memlock.py <rut-binary>", file=sys.stderr)
        return 2
    binary = sys.argv[1]
    if has_cap_ipc_lock():
        skip("CAP_IPC_LOCK held; RLIMIT_MEMLOCK does not apply")
    _, hard = resource.getrlimit(resource.RLIMIT_MEMLOCK)
    limit = LIMIT_KIB * 1024
    if hard != resource.RLIM_INFINITY and hard < limit:
        limit = hard

    def lower():
        resource.setrlimit(resource.RLIMIT_MEMLOCK, (limit, hard))

    try:
        result = subprocess.run(
            [binary, "0", "--shards", "2", "--no-pin", "--drain", "0"],
            capture_output=True,
            text=True,
            timeout=10,
            preexec_fn=lower,
        )
    except subprocess.TimeoutExpired as exc:
        err = (exc.stderr or b"").decode(errors="replace")
        if "Backend: epoll" in err:
            # The one-entry startup probe already failed: other processes of
            # this user hold locked memory beyond the lowered limit.
            skip("io_uring unavailable under the lowered limit (locked memory held elsewhere)")
        skip("server started despite a tiny RLIMIT_MEMLOCK; rings are not charged to it")
    output = result.stdout + result.stderr
    if "Backend: io_uring" not in output:
        skip("io_uring backend unavailable")
    if result.returncode == 0:
        skip("server started despite a tiny RLIMIT_MEMLOCK")
    if "Failed to init shard 0 (errno=12, source=2)" not in output:
        raise AssertionError(f"expected ENOMEM at shard 0: {output!r}")
    if result.returncode != 1:
        raise AssertionError(f"exit code {result.returncode}, expected 1: {output!r}")
    if "epoll" in output:
        raise AssertionError(f"unexpected backend fallback: {output!r}")
    limit_kib = limit // 1024
    for needle in (
        "RLIMIT_MEMLOCK",
        f"soft {limit_kib} KiB",
        f"{PER_SHARD_KIB} KiB per shard",
        f"{PER_SHARD_KIB * 2} KiB for 2 shard(s)",
        "0 shard(s) initialised before it",
        "ulimit -l",
        "LimitMEMLOCK",
        "--ulimit memlock",
        "CAP_IPC_LOCK",
        "--shards N",
    ):
        if needle not in output:
            raise AssertionError(f"diagnostic lacks {needle!r}: {output!r}")
    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
