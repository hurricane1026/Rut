#!/usr/bin/env python3
"""Opt-in, process-scoped kernel diagnostics; no runtime/build dependency."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import sys
import time


GROUPS = ("tcp", "sched", "fault", "rx-copy", "stacks")
ARMED_MARKER = "RUT_TRACE_ARMED"


def secure_text(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        stream = os.fdopen(fd, "w")
        fd = None
        with stream:
            stream.write(text)
    except BaseException:
        if fd is not None:
            os.close(fd)
        raise


def open_output_dir(path):
    """Create and pin a private output directory without pathname races."""
    parent_path, name = path.parent, path.name
    parent_fd = os.open(parent_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parent_stat = os.fstat(parent_fd)
        parent_mode = parent_stat.st_mode
        trusted_owner = (parent_stat.st_uid == os.geteuid() and
                         ((parent_mode & 0o022) == 0 or parent_mode & 0o1000))
        if not trusted_owner:
            raise PermissionError("output parent is not a trusted directory")
        os.mkdir(name, mode=0o700, dir_fd=parent_fd)
        out_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                         dir_fd=parent_fd)
        try:
            out_stat = os.fstat(out_fd)
            entry_stat = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if (out_stat.st_dev, out_stat.st_ino) != (entry_stat.st_dev, entry_stat.st_ino):
                raise RuntimeError("output directory changed during creation")
            if out_stat.st_uid != os.geteuid() or out_stat.st_mode & 0o077:
                raise PermissionError("output directory is not private")
            os.fchmod(out_fd, 0o700)
            return out_fd
        except BaseException:
            os.close(out_fd)
            raise
    finally:
        os.close(parent_fd)


def valid_attached(event):
    data = event.get("data") if isinstance(event, dict) else None
    return (isinstance(event, dict) and event.get("type") == "attached_probes" and
            isinstance(data, dict) and type(data.get("probes")) is int and
            data["probes"] > 0)


def valid_armed(event):
    if not isinstance(event, dict) or event.get("type") != "printf":
        return False
    data = event.get("data")
    return isinstance(data, str) and data.strip() == ARMED_MARKER


def event_seen(path, predicate):
    if not path.exists():
        return False
    try:
        lines = path.read_text().splitlines()
    except OSError:
        return False
    for line in lines:
        try:
            if predicate(json.loads(line)):
                return True
        except (json.JSONDecodeError, TypeError):
            continue
    return False


def process_identity(pid):
    base = Path(f"/proc/{pid}")
    tgid = next(line.split()[1] for line in (base / "status").read_text().splitlines()
                if line.startswith("Tgid:"))
    if int(tgid) != pid:
        raise ValueError(f"{pid} is a thread ID; supply its process PID (TGID {tgid})")
    fields = (base / "stat").read_text().rsplit(")", 1)[1].split()
    return {"pid": pid, "start_ticks": int(fields[19]), "state": fields[0],
            "comm": (base / "comm").read_text().strip(),
            "exe": os.readlink(base / "exe")}


def generate(pids, duration, front_port, origin_port, groups):
    """Only validated integers and fixed probe names enter the program."""
    groups = set(groups)
    if "rx-copy" in groups:
        groups.add("tcp")
    start = [f"@targets[{p}] = 1;" for p in sorted(set(pids))]
    code = ["BEGIN { " + " ".join(start) + " }",
            f'self:signal:SIGUSR1 {{ @stop_ns = nsecs + {duration} * 1000000000; '
            '@armed = 1; printf("RUT_TRACE_ARMED\\n"); }',
            'interval:ms:100 /@armed && nsecs >= @stop_ns/ { exit(); }']
    transient = ["targets", "armed", "stop_ns", "exiting"]
    if "tcp" in groups:
        remote = "$sk->__sk_common.skc_dport"
        if sys.byteorder == "little":
            remote = f"bswap({remote})"
        for direction, function, length in ((1, "tcp_recvmsg", "len"),
                                            (2, "tcp_sendmsg", "size")):
            code.append(f"""
fentry:{function} /@armed && @targets[pid]/ {{
    $sk = args.sk;
    $side = 0;
    if ($sk->__sk_common.skc_num == {front_port}) {{ $side = 1; }}
    else if ({remote} == {origin_port}) {{ $side = 2; }}
    @tcp_start[tid, {direction}] = nsecs;
    @tcp_side[tid, {direction}] = $side;
    @tcp_active[tid] = {direction};
    @tcp_calls[pid, {direction}, $side] = count();
    @tcp_requested_bytes[pid, {direction}, $side] = sum(args.{length});
}}
fexit:{function} /@armed && @tcp_start[tid, {direction}]/ {{
    $side = @tcp_side[tid, {direction}];
    $ns = (uint64)((int64)nsecs - (int64)@tcp_start[tid, {direction}]);
    @tcp_completed_calls[pid, {direction}, $side] = count();
    @tcp_elapsed_ns[pid, {direction}, $side] = sum($ns);
    @tcp_latency_us[pid, {direction}, $side] = hist($ns / 1000);
    $ret = (int64)retval;
    if ($ret > 0) {{
        @tcp_returned_bytes[pid, {direction}, $side] = sum($ret);
    }} else if ($ret < 0) {{
        @tcp_errors[pid, {direction}, $side, $ret] = count();
    }} else {{ @tcp_zero_returns[pid, {direction}, $side] = count(); }}
    delete(@tcp_start[tid, {direction}]);
    delete(@tcp_side[tid, {direction}]);
    delete(@tcp_active[tid]);
}}
""")
        transient += ["tcp_start", "tcp_side", "tcp_active"]
    if "rx-copy" in groups:
        for direction, function in ((1, "skb_copy_datagram_iter"),):
            code.append(f"""
fentry:{function} /@armed && @tcp_active[tid] == {direction}/ {{
    @copy_start[tid, {direction}] = nsecs;
    @copy_length[tid, {direction}] = args.len;
}}
fexit:{function} /@armed && @copy_start[tid, {direction}]/ {{
    $side = @tcp_side[tid, {direction}];
    $ns = (uint64)((int64)nsecs - (int64)@copy_start[tid, {direction}]);
    @copy_calls[pid, {direction}, $side] = count();
    @copy_elapsed_ns[pid, {direction}, $side] = sum($ns);
    if (retval == 0) {{
        @copy_success_bytes[pid, {direction}, $side] = sum(@copy_length[tid, {direction}]);
    }} else {{ @copy_errors[pid, {direction}, $side] = count(); }}
    @copy_latency_us[pid, {direction}, $side] = hist($ns / 1000);
    delete(@copy_start[tid, {direction}]);
    delete(@copy_length[tid, {direction}]);
}}
""")
        transient += ["copy_start", "copy_length"]
    if "sched" in groups:
        code.append("""
rawtracepoint:sched_wakeup,rawtracepoint:sched_wakeup_new {
    $task = (struct task_struct *)arg0;
    if (@armed && @targets[$task->tgid] && !@queued[$task->pid]) {
        @queued[$task->pid] = nsecs;
    }
}
// Linux 6.x: preempt, prev, next, prev_state (snapshot) arguments.
rawtracepoint:sched_switch {
    $prev = (struct task_struct *)arg1;
    $next = (struct task_struct *)arg2;
    if (@exiting[$prev->pid]) {
        delete(@exiting[$prev->pid]);
        delete(@queued[$prev->pid]);
        delete(@offcpu[$prev->pid]);
    } else if (@armed && @targets[$prev->tgid]) {
        @offcpu[$prev->pid] = nsecs;
        if (arg0 || arg3 == 0) { @queued[$prev->pid] = nsecs; }
    }
    if (@armed && @targets[$next->tgid] && !@exiting[$next->pid]) {
        if (@queued[$next->pid]) {
            $ns = (uint64)((int64)nsecs - (int64)@queued[$next->pid]);
            @runqueue_samples[$next->tgid] = count();
            @runqueue_ns[$next->tgid] = sum($ns);
            @runqueue_us[$next->tgid] = hist($ns / 1000);
            delete(@queued[$next->pid]);
        }
        if (@offcpu[$next->pid]) {
            $ns = (uint64)((int64)nsecs - (int64)@offcpu[$next->pid]);
            @offcpu_samples[$next->tgid] = count();
            @offcpu_ns[$next->tgid] = sum($ns);
            @offcpu_us[$next->tgid] = hist($ns / 1000);
            delete(@offcpu[$next->pid]);
        }
    }
}
""")
        transient += ["queued", "offcpu"]
    if "fault" in groups:
        code += ["software:minor-faults:1 /@armed && @targets[pid]/ { @minor_faults[pid] = count(); }",
                 "software:major-faults:1 /@armed && @targets[pid]/ { @major_faults[pid] = count(); }"]
    if "stacks" in groups:
        code.append("profile:hz:99 /@armed && @targets[pid]/ { @kernel_stacks[pid, kstack(24)] = count(); }")
    cleanup = []
    if "tcp" in groups:
        cleanup += [f"delete(@{name}[$task->pid, {d}]);"
                    for name in ("tcp_start", "tcp_side") for d in (1, 2)]
        cleanup += ["delete(@tcp_active[$task->pid]);"]
    if "rx-copy" in groups:
        cleanup += [f"delete(@{name}[$task->pid, 1]);"
                    for name in ("copy_start", "copy_length")]
    if "sched" in groups:
        cleanup += ["delete(@queued[$task->pid]);", "delete(@offcpu[$task->pid]);"]
    code.append("""
rawtracepoint:sched_process_exec {
    $task = (struct task_struct *)arg0;
    // Lifecycle identity must be recorded even during attachment, before arm.
    if (@targets[$task->tgid]) {
        @target_execs[$task->tgid] = count();
        delete(@targets[$task->tgid]);
    }
}
rawtracepoint:sched_process_exit {
    $task = (struct task_struct *)arg0;
    if (@targets[$task->tgid] || @target_execs[$task->tgid]) {
        @thread_exits[$task->tgid] = count();
        @exiting[$task->pid] = 1;
        """ + " ".join(cleanup) + """
        if ($task->pid == $task->tgid) { delete(@targets[$task->tgid]); }
    }
}
""")
    code.append('END { printf("RUT_TRACE_END\\n"); ' +
                " ".join(f"clear(@{name});" for name in transient) + " }")
    return "\n".join(code).replace("delete(@", "$ignored = delete(@")


def read_results(path):
    maps, lost, attached, armed, ended = {}, [], False, False, False
    diagnostics = []
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            diagnostics.append(line)
            continue
        if not isinstance(event, dict):
            diagnostics.append(line)
            continue
        kind, data = event.get("type"), event.get("data")
        if kind in ("map", "hist", "lhist", "stats") and isinstance(data, dict):
            maps.update(data)
        elif kind in ("lost_events", "lost", "error", "warning"):
            lost.append(event)
        elif valid_attached(event):
            attached = True
        elif kind == "printf":
            armed |= valid_armed(event)
            ended |= isinstance(data, str) and data.strip() == "RUT_TRACE_END"
        else:
            diagnostics.append(line)
    return {"maps": maps, "loss_or_errors": lost, "attached": attached,
            "armed": armed, "ready": attached and armed, "ended": ended,
            "stdout_diagnostics": diagnostics}


def tcp_rows(maps):
    rows = []
    for key, calls in maps.get("@tcp_completed_calls", {}).items():
        pid, direction, side = (int(value.strip()) for value in key.split(","))
        elapsed = maps.get("@tcp_elapsed_ns", {}).get(key, 0)
        rows.append({"pid": pid, "direction": {1: "recv", 2: "send"}[direction],
                     "side": {0: "other", 1: "downstream", 2: "upstream"}[side],
                     "completed_calls": calls,
                     "returned_bytes": maps.get("@tcp_returned_bytes", {}).get(key, 0),
                     "inclusive_elapsed_ns": elapsed,
                     "mean_elapsed_us": elapsed / calls / 1000 if calls else None})
    return sorted(rows, key=lambda row: (row["pid"], row["side"], row["direction"]))


def stop_tracer(proc):
    """Signal only our tracer's process group, never any traced process."""
    if proc.poll() is None:
        try:
            os.killpg(proc.pid, signal.SIGINT)
        except ProcessLookupError:
            proc.wait()
            return
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, action="append", required=True,
                        help="host TGID; repeat for multiple workers (not recursive)")
    parser.add_argument("--duration", type=int, default=15)
    parser.add_argument("--front-port", type=int, default=8987)
    parser.add_argument("--origin-port", type=int, default=9987)
    parser.add_argument("--groups", nargs="+", choices=GROUPS, default=["tcp", "sched", "fault"])
    parser.add_argument("--bpftrace", default="bpftrace", help="executable or wrapper path")
    parser.add_argument("--output", type=Path, help="new output directory; never overwritten")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--emit", action="store_true", help="print program without loading probes")
    modes.add_argument("--check", action="store_true", help="load/attach/detach probes only")
    args = parser.parse_args(argv)
    if any(p <= 0 for p in args.pid) or len(set(args.pid)) > 32:
        parser.error("supply 1–32 positive PIDs")
    if not 1 <= args.duration <= 3600:
        parser.error("duration must be 1–3600 seconds")
    if not all(1 <= p <= 65535 for p in (args.front_port, args.origin_port)):
        parser.error("ports must be 1–65535")
    if args.front_port == args.origin_port:
        parser.error("front and origin ports must differ")
    script = generate(args.pid, args.duration, args.front_port, args.origin_port, args.groups)
    if args.emit:
        print(script)
        return 0
    if args.output is None:
        parser.error("--output is required unless using --emit")
    if args.output.is_symlink():
        parser.error("output must not be a symlink")
    display_out = args.output.absolute()
    out_fd = None
    try:
        out_fd = open_output_dir(args.output)
        out = Path(f"/proc/self/fd/{out_fd}")
    except FileExistsError:
        parser.error(f"output already exists: {display_out}")
    except (OSError, RuntimeError) as exc:
        parser.error(f"cannot securely create output directory: {exc}")
    program = out / "program.bt"
    try:
        secure_text(program, script)
    except BaseException:
        os.close(out_fd)
        raise
    groups = sorted(set(args.groups) | ({"tcp"} if "rx-copy" in args.groups else set()))
    status = {"completed": False, "usable": False, "mode": "check" if args.check else "trace",
              "kernel": platform.release(), "machine": platform.machine(), "groups": groups,
              "duration_seconds": args.duration, "front_port": args.front_port,
              "origin_port": args.origin_port, "started_at": time.time(),
              "program_sha256": hashlib.sha256(script.encode()).hexdigest(),
              "attached": False, "armed": False}
    proc = None
    previous_term = signal.getsignal(signal.SIGTERM)

    def interrupted(signum, _frame):
        raise KeyboardInterrupt(f"signal {signum}")

    signal.signal(signal.SIGTERM, interrupted)
    try:
        status["targets_before"] = [process_identity(p) for p in sorted(set(args.pid))]
        if platform.system() != "Linux" or int(platform.release().split(".")[0]) < 6:
            raise RuntimeError("Linux 6.x or newer is required for these probe signatures")
        version = subprocess.run([args.bpftrace, "--version"], capture_output=True, text=True,
                                 check=True, timeout=30)
        status["bpftrace_version"] = version.stdout.strip()
        match = re.search(r"v?(\d+)\.(\d+)\.(\d+)", version.stdout)
        if not match or tuple(map(int, match.groups())) < (0, 25, 0):
            raise RuntimeError("bpftrace >= 0.25.0 is required")
        command = [args.bpftrace, "-f", "json", "-B", "line"]
        if args.check:
            command.append("--dry-run")
        command.append(str(program))
        status["command"] = command
        print(f"Loading probes; waiting for attachment and arm acknowledgement: {out / 'trace.jsonl'}", flush=True)
        trace_fd = os.open(out / "trace.jsonl", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            stderr_fd = os.open(out / "stderr.log", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except BaseException:
            os.close(trace_fd)
            raise
        with os.fdopen(trace_fd, "w") as stdout, os.fdopen(stderr_fd, "w") as stderr:
            proc = subprocess.Popen(command, stdout=stdout, stderr=stderr,
                                    start_new_session=True, pass_fds=(out_fd,))
            try:
                if not args.check:
                    raw = out / "trace.jsonl"
                    deadline = time.monotonic() + 30
                    while not event_seen(raw, valid_attached):
                        if proc.poll() is not None:
                            raise RuntimeError("bpftrace exited before attachment")
                        if time.monotonic() > deadline:
                            raise RuntimeError("timed out waiting for attached_probes")
                        time.sleep(0.05)
                    status["attached"] = True
                    proc.send_signal(signal.SIGUSR1)
                    deadline = time.monotonic() + 30
                    while not event_seen(raw, valid_armed):
                        if proc.poll() is not None:
                            raise RuntimeError("bpftrace exited before arm acknowledgement")
                        if time.monotonic() > deadline:
                            raise RuntimeError("timed out waiting for RUT_TRACE_ARMED")
                        time.sleep(0.05)
                    status["armed"] = True
                status["returncode"] = proc.wait(timeout=args.duration + 120)
            finally:
                stop_tracer(proc)
        status["targets_after"] = []
        for before in status["targets_before"]:
            try:
                after = process_identity(before["pid"])
            except OSError:
                after = {"pid": before["pid"], "exited": True}
            status["targets_after"].append(after)
        status["targets_unchanged"] = all(
            a.get("start_ticks") == b.get("start_ticks") and a.get("exe") == b.get("exe")
            and b.get("state") != "Z"
            for a, b in zip(status["targets_before"], status["targets_after"]))
        result = read_results(out / "trace.jsonl")
        result["tcp"] = tcp_rows(result["maps"])
        secure_text(out / "summary.json", json.dumps(result, indent=2) + "\n")
        warnings = (out / "stderr.log").read_text()
        status["diagnostic_warnings"] = bool(warnings.strip()) or bool(result["stdout_diagnostics"])
        status["completed"] = status["returncode"] == 0 and (
            args.check or (result["ready"] and result["ended"]))
        # Conservatively require reviewing any tool warning before using results.
        status["usable"] = (not args.check and status["completed"] and
                            status["targets_unchanged"] and not result["loss_or_errors"]
                            and not result["maps"].get("@target_execs")
                            and not status["diagnostic_warnings"])
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, KeyboardInterrupt) as exc:
        status["error"] = str(exc) or type(exc).__name__
        print(f"Tracing failed: {status['error']}", file=sys.stderr)
    finally:
        if proc is not None:
            stop_tracer(proc)
        signal.signal(signal.SIGTERM, previous_term)
        status["finished_at"] = time.time()
        secure_text(out / "status.json", json.dumps(status, indent=2) + "\n")
        if out_fd is not None:
            os.close(out_fd)
            out_fd = None
    print(f"Evidence: {display_out}; completed={status['completed']}, usable={status['usable']}")
    return 0 if (status["completed"] if args.check else status["usable"]) else 1


if __name__ == "__main__":
    sys.exit(main())
