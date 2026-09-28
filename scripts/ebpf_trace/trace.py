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
    code = ["BEGIN { " + " ".join(start) +
            ' printf("RUT_TRACE_READY\\n"); }',
            f"interval:s:{duration} {{ exit(); }}"]
    transient = ["targets"]
    if "tcp" in groups:
        remote = "$sk->__sk_common.skc_dport"
        if sys.byteorder == "little":
            remote = f"bswap({remote})"
        for direction, function, length in ((1, "tcp_recvmsg", "len"),
                                            (2, "tcp_sendmsg", "size")):
            code.append(f"""
fentry:{function} /@targets[pid]/ {{
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
fexit:{function} /@tcp_start[tid, {direction}]/ {{
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
fentry:{function} /@tcp_active[tid] == {direction}/ {{
    @copy_start[tid, {direction}] = nsecs;
    @copy_length[tid, {direction}] = args.len;
}}
fexit:{function} /@copy_start[tid, {direction}]/ {{
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
    if (@targets[$task->tgid] && !@queued[$task->pid]) {
        @queued[$task->pid] = nsecs;
    }
}
// Linux 6.x: preempt, prev, next, prev_state (snapshot) arguments.
rawtracepoint:sched_switch {
    $prev = (struct task_struct *)arg1;
    $next = (struct task_struct *)arg2;
    if (@targets[$prev->tgid]) {
        @offcpu[$prev->pid] = nsecs;
        if (arg0 || arg3 == 0) { @queued[$prev->pid] = nsecs; }
    }
    if (@targets[$next->tgid]) {
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
        code += ["software:minor-faults:1 /@targets[pid]/ { @minor_faults[pid] = count(); }",
                 "software:major-faults:1 /@targets[pid]/ { @major_faults[pid] = count(); }"]
    if "stacks" in groups:
        code.append("profile:hz:99 /@targets[pid]/ { @kernel_stacks[pid, kstack(24)] = count(); }")
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
    if (@targets[$task->tgid]) {
        @target_execs[$task->tgid] = count();
        delete(@targets[$task->tgid]);
    }
}
rawtracepoint:sched_process_exit {
    $task = (struct task_struct *)arg0;
    if (@targets[$task->tgid]) {
        @thread_exits[$task->tgid] = count();
        """ + " ".join(cleanup) + """
        if ($task->pid == $task->tgid) { delete(@targets[$task->tgid]); }
    }
}
""")
    code.append('END { printf("RUT_TRACE_END\\n"); ' +
                " ".join(f"clear(@{name});" for name in transient) + " }")
    return "\n".join(code).replace("delete(@", "$ignored = delete(@")


def read_results(path):
    maps, lost, ready, ended = {}, [], False, False
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
        elif kind == "printf":
            ready |= "RUT_TRACE_READY" in str(data)
            ended |= "RUT_TRACE_END" in str(data)
        elif kind != "attached_probes":
            diagnostics.append(line)
    return {"maps": maps, "loss_or_errors": lost, "ready": ready, "ended": ended, "stdout_diagnostics": diagnostics}


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
    out = args.output.resolve()
    try:
        out.mkdir(parents=True, exist_ok=False)
    except FileExistsError:
        parser.error(f"output already exists: {out}")
    program = out / "program.bt"
    program.write_text(script)
    groups = sorted(set(args.groups) | ({"tcp"} if "rx-copy" in args.groups else set()))
    status = {"completed": False, "usable": False, "mode": "check" if args.check else "trace",
              "kernel": platform.release(), "machine": platform.machine(), "groups": groups,
              "duration_seconds": args.duration, "front_port": args.front_port,
              "origin_port": args.origin_port, "started_at": time.time(),
              "program_sha256": hashlib.sha256(script.encode()).hexdigest()}
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
        print(f"Loading probes; readiness marker and maps: {out / 'trace.jsonl'}", flush=True)
        with (out / "trace.jsonl").open("w") as stdout, (out / "stderr.log").open("w") as stderr:
            proc = subprocess.Popen(command, stdout=stdout, stderr=stderr, start_new_session=True)
            try:
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
        (out / "summary.json").write_text(json.dumps(result, indent=2) + "\n")
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
        (out / "status.json").write_text(json.dumps(status, indent=2) + "\n")
    print(f"Evidence: {out}; completed={status['completed']}, usable={status['usable']}")
    return 0 if (status["completed"] if args.check else status["usable"]) else 1


if __name__ == "__main__":
    sys.exit(main())
