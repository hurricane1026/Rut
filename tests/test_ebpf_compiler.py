#!/usr/bin/env python3
"""Exercise Rut source -> compiler subprocess -> native artifact -> bytecode export."""
import argparse
import json
import shutil
import struct
import sys
from pathlib import Path
import subprocess
import tempfile

SOURCE = '''listen 127.0.0.1:0
upstream b at "127.0.0.1:9000"
upstream h2 {
    host: "127.0.0.1"
    port: 9001
    protocol: .http2
}
let counts = Cache<IP, i64>(capacity: 64)
func require_path(_ req: i32) -> i32 {
    guard req.path == "/chain" else { respond 403 }
    0
}
chain gate { before require_path(req) }
route GET "/plain" { return forward(b, load_balance: .roundRobin) }
route GET "/h2" { return forward(h2, load_balance: .roundRobin) }
route GET "/headers" {
    return forward(b, load_balance: .roundRobin, request_policy: { version: .http11, host: .upstream,
        connection: .omit, strip_headers: [.connection, .keepAlive, .te, .expect, .upgrade] })
}
route GET "/static" { return 200 }
route POST "/body" { guard req.body == "ok" else { return 400 } return forward(b, load_balance: .roundRobin) }
route GET "/regex" { guard req.path.matches(re"/regex") else { return 403 } return forward(b, load_balance: .roundRobin) }
@rateLimit(limit: 2, window: 1m)
route GET "/limited" { return forward(b, load_balance: .roundRobin) }
route GET "/state" { counts.set(req.remoteAddr, 1) return forward(b, load_balance: .roundRobin) }
route GET "/chain" use chain gate { return forward(b, load_balance: .roundRobin) }
route GET "/buffered" {
    return forward(b, load_balance: .roundRobin,
      response_policy: {version: .http11, framing: .contentLength,
        connection: .request, server: "rut", date: .current, hide_headers: []},
      failure_policy: {version: .http11, status: 502, reason: "Bad Gateway",
        content_type: "text/plain", server: "rut", date: .current,
        connection: .request, body: b"bad"},
      timeout_failure_policy: {version: .http11, status: 504,
        reason: "Gateway Time-out", content_type: "text/plain", server: "rut",
        date: .current, connection: .request, body: b"slow"},
      response_read_timeout: 1s, response_buffering: .completeContentLength)
}
'''


def run(server, *args):
    return subprocess.run([str(server), *map(str, args)], capture_output=True, text=True, timeout=30)


def check_crossing_budget_transition(data):
    """Execute each emitted crossing transition on a nonzero synthetic state."""
    instructions = [struct.unpack_from("BBhi", data, offset)
                    for offset in range(0, len(data), 8)]
    owned = 0x80000000
    owned_immediate = -0x80000000
    budget_mask = 0x3FFFFFFF
    clear_mask = (-1 << 30) & 0xFFFFFFFF
    clear_immediate = -0x40000000
    transitions = 0
    for index, (opcode, registers, _offset, immediate) in enumerate(instructions[:-3]):
        dst, src = registers & 0x0F, registers >> 4
        if (opcode, dst, immediate) != (0xB4, 2, owned_immediate):
            continue
        mask = instructions[index + 1]
        shift = instructions[index + 2]
        merge = instructions[index + 3]
        assert mask[:2] == (0x57, 2) and mask[3] == clear_immediate, mask
        assert shift[:3] == (0x67, 2, 0) and shift[2] == 0, shift
        assert merge[0] == 0x4F and (merge[1] & 0x0F) == 3 and merge[1] >> 4 == 2, merge
        control = 123 | owned
        control &= clear_mask
        control <<= 32
        passed = 0x12345678
        result = control | passed
        assert result & 0xFFFFFFFF == passed
        assert (result >> 32) & budget_mask == 0
        assert result & (owned << 32), result
        transitions += 1
    assert transitions == 4, transitions


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--enabled", choices=("0", "1"), required=True)
    args = parser.parse_args()
    server = args.server.resolve()
    with tempfile.TemporaryDirectory(prefix="rut ebpf compiler ") as directory:
        root = Path(directory)
        source = root / "program with spaces.rut"
        source.write_text(SOURCE)
        result = run(server, source, "--ebpf-plan")
        if args.enabled == "0":
            assert result.returncode != 0 and "RUT_ENABLE_EBPF=ON" in result.stderr, result
            print("Disabled build rejects eBPF planning explicitly")
            return
        assert result.returncode == 0, result.stderr
        plan = json.loads(result.stdout)
        assert plan["active_routes"] == 0 and plan["runtime_handoff"] == "unavailable", plan
        assert plan["candidate_count"] == 2, plan
        routes = {route["path"]: route for route in plan["routes"]}
        assert routes["/plain"]["decision"] == "body-candidate", routes
        assert routes["/headers"]["request_policy_id"] == 1, routes
        reasons = {"/h2": "http2-upstream-framing", "/static": "not-a-terminal-forward", "/body": "request-body-access",
                   "/regex": "regex-in-user-space", "/limited": "rate-limit-or-throttle",
                   "/state": "user-computation-or-side-effects", "/chain": "control-flow-not-proven",
                   "/buffered": "forward-policy-bundle"}
        for path, reason in reasons.items():
            assert routes[path]["decision"] == "userspace" and routes[path]["reason"] == reason, routes[path]
        prefix = root / "export with spaces"
        result = run(server, source, "--emit-ebpf", prefix)
        assert result.returncode == 0, result.stderr
        emitted = json.loads(Path(str(prefix) + ".json").read_text())
        assert emitted == plan, emitted
        for kind in ("parser", "verdict"):
            data = Path(f"{prefix}.{kind}.bpf").read_bytes()
            assert len(data) == plan["bytecode"][f"{kind}_bytes"]
            # Relocation slots must carry placeholders, never compiler process FDs.
            for index in (3, 6) + ((22,) if kind == "verdict" else ()):
                assert data[index * 8 + 4:index * 8 + 8] == bytes(4), data.hex()
        handoff = plan["handoff"]
        for kind, length, relocations in (
                ("packet-verdict", "verdict_bytes", ("verdict_state_map", "verdict_target_map", "verdict_ring_map")),
                ("handoff-commit", "commit_bytes", ("commit_command_map", "commit_state_map"))):
            data = Path(f"{prefix}.{kind}.bpf").read_bytes()
            assert len(data) == handoff[length]
            for name in relocations:
                index = handoff["relocations"][name]
                assert data[index * 8 + 4:index * 8 + 8] == bytes(4), name
        check_crossing_budget_transition(Path(str(prefix) + ".packet-verdict.bpf").read_bytes())
        preserved = {suffix: Path(str(prefix) + suffix).read_bytes()
                     for suffix in (".parser.bpf", ".verdict.bpf", ".packet-verdict.bpf", ".handoff-commit.bpf", ".json")}
        result = run(server, source, "--emit-ebpf", prefix)
        assert result.returncode != 0, result
        for suffix, content in preserved.items():
            assert Path(str(prefix) + suffix).read_bytes() == content
        partial = root / "partial"
        Path(str(partial) + ".json").write_text("existing")
        result = run(server, source, "--emit-ebpf", partial)
        assert result.returncode != 0, result
        assert not Path(str(partial) + ".parser.bpf").exists()
        assert not Path(str(partial) + ".verdict.bpf").exists()
        assert not Path(str(partial) + ".packet-verdict.bpf").exists()
        assert not Path(str(partial) + ".handoff-commit.bpf").exists()
        assert Path(str(partial) + ".json").read_text() == "existing"
        # The consumer must reject malformed plans received over the real compiler pipe.
        source.write_text('upstream b at "127.0.0.1:9000"\nroute GET "/" { return forward(b, load_balance: .roundRobin) }\n')
        compiler = server.parent / "rut-compile"
        with_plan = subprocess.run([str(compiler), str(source), "2", "--ebpf-plan"],
                                   capture_output=True, check=True, timeout=30).stdout
        without_plan = subprocess.run([str(compiler), str(source), "2"],
                                      capture_output=True, check=True, timeout=30).stdout
        verdict = preserved[".verdict.bpf"]
        assert with_plan.count(verdict) == 1
        position = with_plan.index(verdict) + 22 * 8 + 4
        corrupted = with_plan[:position] + bytes((99, 0, 0, 0)) + with_plan[position + 4:]
        packet = preserved[".packet-verdict.bpf"]
        assert with_plan.count(packet) == 1
        position = with_plan.index(packet) + handoff["relocations"]["verdict_ring_map"] * 8 + 4
        corrupt_ring = with_plan[:position] + bytes((99, 0, 0, 0)) + with_plan[position + 4:]
        consumer_dir = root / "consumer"
        consumer_dir.mkdir()
        consumer = consumer_dir / "rut"
        shutil.copy2(server, consumer)
        helper = consumer_dir / "rut-compile"
        for payload, flags, expected in (
                (corrupted, ("--ebpf-plan",), "invalid native eBPF plan"),
                (corrupt_ring, ("--ebpf-plan",), "invalid native eBPF plan"),
                (with_plan, (), "native eBPF plan framing mismatch"),
                (without_plan, ("--ebpf-plan",), "native eBPF plan framing mismatch")):
            helper.write_text(f"#!{sys.executable}\nimport sys\n"
                              f"sys.stdout.buffer.write(bytes.fromhex({payload.hex()!r}))\n")
            helper.chmod(0o700)
            result = run(consumer, source, *flags)
            assert result.returncode != 0 and expected in result.stderr, result
            assert "Listening on port" not in result.stderr
        source.write_text('route GET "/" { return 200 }\n')
        result = run(server, source, "--ebpf-plan")
        assert result.returncode == 0 and json.loads(result.stdout)["candidate_count"] == 0
        result = run(server, source, "--emit-ebpf", root / "none")
        assert result.returncode != 0 and "no eBPF body candidate" in result.stderr
        assert not list(root.glob("none.*"))
        for arguments in (("--emit-ebpf",), ("--ebpf-plan",),
                          (source, "--ebpf-plan", "--h2")):
            result = run(server, *arguments)
            assert result.returncode != 0, result
    print("RIR decisions, compiler artifact, bytecode export and output rollback verified")


if __name__ == "__main__":
    main()
