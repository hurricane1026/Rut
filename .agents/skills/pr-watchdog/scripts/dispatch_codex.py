#!/usr/bin/env python3
"""Queue one poller event into a persistent Codex coordinator session."""

import argparse
import json
import subprocess
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--thread", required=True, help="persistent Codex session UUID or exact name")
    args = parser.parse_args()
    payload = sys.stdin.read().strip()
    if not payload:
        parser.error("expected one JSON event on stdin")
    try:
        event = json.loads(payload)
    except json.JSONDecodeError as error:
        parser.error(f"invalid JSON event: {error}")
    message = (
        "PR watchdog event received. Reconcile all watched PRs, then schedule the required "
        "Sol/Luna work and continue the review/CI/rebase loop. Do not merge.\n"
        f"Event:\n{json.dumps(event, ensure_ascii=False, sort_keys=True)}"
    )
    result = subprocess.run(
        ["codex", "queue", "--thread", args.thread, "--message", message],
        check=False,
    )
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
