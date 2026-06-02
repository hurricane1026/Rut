#!/usr/bin/env python3
"""Check that Rut's runtime-state TLA+ model tracks the C++ surface.

This is a structural consistency gate. If TLC is available, the script also
runs the model checker against spec/runtime_state.cfg.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "spec" / "runtime_state.tla"
CFG = ROOT / "spec" / "runtime_state.cfg"
CONNECTION_BASE = ROOT / "include" / "rut" / "runtime" / "connection_base.h"
DEBUG_H = ROOT / "include" / "rut" / "runtime" / "debug.h"
TEST_NETWORK = ROOT / "tests" / "test_network.cc"
CALLBACKS_IMPL = ROOT / "include" / "rut" / "runtime" / "callbacks_impl.h"
EVENT_LOOP = ROOT / "include" / "rut" / "runtime" / "event_loop.h"
EPOLL_LOOP = ROOT / "include" / "rut" / "runtime" / "epoll_event_loop.h"
IOURING_LOOP = ROOT / "include" / "rut" / "runtime" / "iouring_event_loop.h"


def fail(message: str) -> None:
    print(f"runtime-state model check failed: {message}", file=sys.stderr)
    sys.exit(1)


def read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        fail(f"cannot read {path}: {exc}")


def parse_marker_list(spec: str, key: str) -> list[str]:
    pattern = re.compile(rf"^\\\* @rut\.{re.escape(key)}:\s*(.+)$", re.MULTILINE)
    match = pattern.search(spec)
    if not match:
        fail(f"missing @rut.{key} marker in {SPEC}")
    return match.group(1).split()


def parse_action_markers(spec: str) -> dict[str, list[str]]:
    actions: dict[str, list[str]] = {}
    pattern = re.compile(r"^\\\* @rut\.action\s+([A-Za-z0-9_]+):\s*(.+)$", re.MULTILINE)
    for match in pattern.finditer(spec):
        actions[match.group(1)] = match.group(2).split()
    if not actions:
        fail(f"missing @rut.action markers in {SPEC}")
    return actions


def parse_conn_states(header: str) -> list[str]:
    match = re.search(r"enum class ConnState\s*:\s*u8\s*\{(?P<body>.*?)\};", header, re.S)
    if not match:
        fail("ConnState enum not found")
    states: list[str] = []
    for raw in match.group("body").split(","):
        token = raw.split("//", 1)[0].strip()
        if not token or token == "Count":
            continue
        states.append(token)
    return states


def parse_debug_state_names(debug_h: str) -> list[str]:
    match = re.search(r"kConnStateNames\[.*?\]\s*=\s*\{(?P<body>.*?)\};", debug_h, re.S)
    if not match:
        fail("kConnStateNames table not found")
    return re.findall(r'"([^"]+)"', match.group("body"))


def parse_slot_suffixes(debug_h: str) -> list[str]:
    match = re.search(r"enum ConnSlotMask\s*:\s*u8\s*\{(?P<body>.*?)\};", debug_h, re.S)
    if not match:
        fail("ConnSlotMask enum not found")
    slots = re.findall(r"kConnSlot([A-Za-z0-9_]+)\s*=", match.group("body"))
    return slots


def ensure_tla_action_definitions(spec: str, actions: dict[str, list[str]]) -> None:
    for action in actions:
        if not re.search(rf"^{re.escape(action)}\s*==", spec, re.MULTILINE):
            fail(f"@rut.action {action} has no TLA+ action definition")


def ensure_action_tokens(actions: dict[str, list[str]]) -> None:
    corpus = "\n".join(
        read(path)
        for path in (TEST_NETWORK, CALLBACKS_IMPL, EVENT_LOOP, EPOLL_LOOP, IOURING_LOOP)
    )
    for action, tokens in actions.items():
        missing = [token for token in tokens if token not in corpus]
        if missing:
            fail(f"action {action} references missing C++ coverage token(s): {', '.join(missing)}")


def maybe_run_tlc() -> None:
    tlc = shutil.which("tlc")
    tla2tools = os.environ.get("TLA2TOOLS_JAR")
    if tlc:
        cmd = [tlc, "-deadlock", "-config", CFG.name, SPEC.stem]
    elif tla2tools and shutil.which("java"):
        cmd = ["java", "-cp", tla2tools, "tlc2.TLC", "-deadlock", "-config", CFG.name, SPEC.stem]
    else:
        print("TLC not found; skipped model checking after static consistency checks")
        return

    proc = subprocess.run(cmd, cwd=SPEC.parent, text=True)
    if proc.returncode != 0:
        fail(f"TLC exited with status {proc.returncode}")


def main() -> int:
    spec = read(SPEC)
    connection_base = read(CONNECTION_BASE)
    debug_h = read(DEBUG_H)

    spec_states = parse_marker_list(spec, "states")
    cpp_states = parse_conn_states(connection_base)
    debug_states = parse_debug_state_names(debug_h)
    if spec_states != cpp_states:
        fail(f"state mismatch: TLA+ {spec_states} != ConnState {cpp_states}")
    if spec_states != debug_states:
        fail(f"state-name mismatch: TLA+ {spec_states} != debug table {debug_states}")

    spec_slots = parse_marker_list(spec, "slots")
    cpp_slots = parse_slot_suffixes(debug_h)
    if spec_slots != cpp_slots:
        fail(f"slot mismatch: TLA+ {spec_slots} != ConnSlotMask {cpp_slots}")

    actions = parse_action_markers(spec)
    ensure_tla_action_definitions(spec, actions)
    ensure_action_tokens(actions)
    maybe_run_tlc()

    print(
        f"runtime-state model checks passed: {len(spec_states)} states, "
        f"{len(spec_slots)} slots, {len(actions)} actions"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
