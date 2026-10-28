#!/usr/bin/env python3
"""Record the sockmap prototype under explicit host/container security profiles.

No dependency installation or privileged-container mode. Stage the binary,
matching glibc loader/libc, and emitted bytecode in a readable directory first.
Run this script through `sg docker -c ...` if the session lacks its Docker group.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


def command(arguments):
    result = subprocess.run(arguments, capture_output=True, text=True, timeout=30)
    return {"command": arguments, "returncode": result.returncode,
            "stdout": result.stdout, "stderr": result.stderr}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--image", default="nginx:latest")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--profiles", nargs="+", help="Run only the named security profiles")
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("--repeats must be positive")
    stage = args.stage.resolve()
    args.out.mkdir(parents=True, exist_ok=False)
    names = ("probe", "loader", "libc.so.6", "tunnel.parser.bpf", "tunnel.verdict.bpf",
             "tunnel.body-parser.bpf", "tunnel.body-verdict.bpf")
    manifest = {"kernel": list(os.uname()), "uid": os.getuid(), "stage": str(stage),
                "sha256": {name: hashlib.sha256((stage / name).read_bytes()).hexdigest()
                           for name in names},
                "image": command(["docker", "image", "inspect", args.image])}
    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    profiles = {
        "host": None,
        "sidecar-default": ["--user", "65532:65532", "--cap-drop", "ALL",
                            "--security-opt", "no-new-privileges=true"],
        "bpf-default-seccomp": ["--cap-drop", "ALL", "--cap-add", "BPF", "--cap-add", "NET_ADMIN"],
        "bpf-default-label": ["--cap-drop", "ALL", "--cap-add", "BPF", "--cap-add", "NET_ADMIN",
                              "--security-opt", "seccomp=unconfined"],
        "bpf-default-seccomp-label-disabled": ["--cap-drop", "ALL", "--cap-add", "BPF", "--cap-add", "NET_ADMIN",
                                                "--security-opt", "label=disable"],
        "bpf-relaxed-label": ["--cap-drop", "ALL", "--cap-add", "BPF", "--cap-add", "NET_ADMIN",
                              "--security-opt", "seccomp=unconfined", "--security-opt", "label=disable"],
    }
    if args.profiles:
        if any(name not in profiles for name in args.profiles):
            parser.error("unknown profile; choose from: " + ", ".join(profiles))
        profiles = {name: profiles[name] for name in args.profiles}
    cases = (("off",), ("auto",), ("required",),
             ("required", "--header-rewrite"),
             ("required", "--header-rewrite", "--bounded-body"),
             ("required", "--header-rewrite", "--bounded-body", "--prequeued-body"),
             ("auto", "--header-rewrite", "--bounded-body", "--prequeued-body"),
             ("auto", "--fail-after-insert", "--header-rewrite"),
             ("required", "--fail-after-insert"))
    observations = []
    for profile, options in profiles.items():
        for repeat in range(args.repeats):
            for case in cases:
                if options is None:
                    argv = [str(stage / "probe"), *case, "--bytecode", str(stage / "tunnel")]
                else:
                    argv = ["docker", "run", "--rm", "--pull=never", *options,
                            "--mount", f"type=bind,src={stage},dst=/probe,readonly",
                            "--entrypoint", "/probe/loader", args.image,
                            "--library-path", "/probe", "/probe/probe", *case,
                            "--bytecode", "/probe/tunnel"]
                observation = {"profile": profile, "repeat": repeat + 1, "case": list(case),
                               **command(argv)}
                observation["records"] = [json.loads(line) for line in observation["stdout"].splitlines()]
                records = observation["records"]
                observations.append(observation)
                (args.out / "results.json").write_text(json.dumps(observations, indent=2) + "\n")
                if case[0] in ("off", "auto"):
                    assert observation["returncode"] == 0, observation
                    assert records[-1]["transfer_ok"] and records[-1]["half_close_ok"], observation
                    assert records[-1]["verified_bytes"] == 2097169, observation
                    expected = 0 if records[-1]["backend"] == "sockmap" else 2097169
                    assert records[-1]["relay_userspace_bytes"] == expected, observation
                    if "--header-rewrite" in case:
                        assert records[-1]["header_userspace_bytes"] == 54, observation
                elif observation["returncode"] == 0:
                    assert records[-1]["transfer_ok"] and records[-1]["half_close_ok"], observation
                    if "--prequeued-body" in case:
                        assert records[0]["stage"] == "prequeued_body" and records[-1]["backend"] == "copy", observation
                    else:
                        assert records[-1]["backend"] == "sockmap", observation
                        assert records[-1]["relay_userspace_bytes"] == 0, observation
                        if "--bounded-body" in case:
                            assert records[-1]["successor_userspace_bytes"] == 17, observation
                else:
                    assert observation["returncode"] == 1 and records[-1]["backend"] == "unavailable", observation
                print(profile, repeat + 1, " ".join(case), observation["returncode"],
                      records[-1].get("backend"), flush=True)
    print(f"Recorded {len(observations)} cases in {args.out}")


if __name__ == "__main__":
    main()
