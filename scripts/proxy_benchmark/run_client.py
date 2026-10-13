#!/usr/bin/env python3
"""Run one wrk sample from the kind worker network namespace."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import time

from common import load_config


def start_and_stamp(docker: str, container: str, stamp: Path, *, timeout: float = 30.0) -> None:
    subprocess.run([docker, "start", container], check=True, text=True,
                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = subprocess.run([docker, "inspect", "--format", "{{.State.Running}}", container],
                               check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if state.stdout.strip() == "true":
            stamp.write_text(f"{time.monotonic():.9f}\n")
            return
        time.sleep(0.02)
    raise RuntimeError(f"client container {container} did not start within {timeout}s")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("--pod-ip", required=True)
    parser.add_argument("--duration", required=True)
    parser.add_argument("--lua", choices=("request.lua", "warmup.lua"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    config = load_config(args.config)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    name = f"proxybench-{config['run_id']}-{args.label}".replace("_", "-")
    client_image = config["image_identities"]["client"]["docker_id"]
    argv = [
        config["tools"]["docker"], "create", "--name", name,
        "--security-opt", "label=disable",
        "--network", f"container:{config['worker_container']}",
        "--cpuset-cpus", config["cpus"]["client"],
        "--mount", f"type=bind,src={config['client_dir']},dst=/benchmark,readonly",
        "--entrypoint", "/usr/local/bin/wrk",
        client_image, "-t2", f"-c{config['concurrency']}", f"-d{args.duration}",
        "--latency", "--timeout", "2s", "-s", f"/benchmark/{args.lua}",
        f"http://{args.pod_ip}:8080/proxy",
    ]
    (output / "command.json").write_text(json.dumps(argv, indent=2) + "\n")
    (output / "image.json").write_text(json.dumps({"reference": config["images"]["client"],
                                                    "image_id": client_image}, indent=2) + "\n")
    created = None
    try:
        p = subprocess.run(argv, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        created = p.stdout.strip()
        (output / "container-id.txt").write_text(created + "\n")
        inspect = subprocess.run([config["tools"]["docker"], "inspect", created], check=True,
                                 text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        (output / "client-container-inspect.json").write_text(inspect.stdout)
        if args.lua == "request.lua":
            start_and_stamp(config["tools"]["docker"], created, output / "measurement-start-monotonic.txt")
            waited = subprocess.run([config["tools"]["docker"], "wait", created], check=True,
                                    text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            sample = subprocess.run([config["tools"]["docker"], "logs", created], check=True,
                                    text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            sample_returncode = int(waited.stdout.strip())
        else:
            sample = subprocess.run([config["tools"]["docker"], "start", "--attach", created],
                                    text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            sample_returncode = sample.returncode
        (output / "wrk.log").write_text(sample.stdout)
        if sample_returncode or "cannot open /benchmark/" in sample.stdout or "METRICS " not in sample.stdout:
            (output / "returncode.txt").write_text(f"{sample_returncode or 125}\n")
            (output / "invalid-reason.txt").write_text("wrk exit failure, Lua access failure, or missing METRICS line\n")
            return sample_returncode or 125
        (output / "returncode.txt").write_text("0\n")
        return 0
    except subprocess.CalledProcessError as error:
        (output / "error.log").write_text(error.stdout or "")
        (output / "returncode.txt").write_text(f"{error.returncode}\n")
        return error.returncode
    finally:
        if created:
            subprocess.run([config["tools"]["docker"], "rm", "-f", created],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"run_client: {error}", file=sys.stderr)
        raise SystemExit(2)
