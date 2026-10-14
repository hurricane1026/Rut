#!/usr/bin/env python3
"""Copy resolved ELF shared libraries for supplied local executables."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def dependencies(binary: Path) -> list[Path]:
    result = subprocess.run(["ldd", str(binary)], text=True, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, check=False)
    if result.returncode:
        raise RuntimeError(f"ldd failed for {binary}:\n{result.stdout}")
    if "not found" in result.stdout:
        raise RuntimeError(f"unresolved dependency for {binary}:\n{result.stdout}")
    paths = []
    for line in result.stdout.splitlines():
        match = re.search(r"(?:=>\s*)?(/[^\s(]+)", line)
        if match:
            source_name = Path(match.group(1))
            path = source_name.resolve(strict=True)
            if path.is_file():
                paths.append((source_name.name, path))
    return paths


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("binaries", nargs="+", type=Path,
                        help="rut, rut-compile, clang and ld from the selected toolchain")
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() and any(output.iterdir()):
        parser.error("--output must be new or empty")
    output.mkdir(parents=True, exist_ok=True)
    copied = {}
    binary_records = []
    for raw in args.binaries:
        binary = raw.resolve(strict=True)
        dependency_records = []
        for soname, library in dependencies(binary):
            dependency_records.append({"soname": soname, "source": str(library),
                                       "bytes": library.stat().st_size, "sha256": sha256(library)})
            destination = output / soname
            if destination.exists():
                if destination.read_bytes() != library.read_bytes():
                    raise RuntimeError(f"library basename collision: {library} and {destination}")
            else:
                shutil.copy2(library, destination)
            copied[soname] = {"bytes": destination.stat().st_size, "sha256": sha256(destination)}
        binary_records.append({"path": str(binary), "bytes": binary.stat().st_size,
                               "sha256": sha256(binary), "dependencies": dependency_records})
    manifest = {"schema": 1, "binaries": binary_records,
                "libraries": [{"soname": name, **copied[name]} for name in sorted(copied)]}
    (output / "runtime-libs.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print("\n".join(f"{name}\t{record['sha256']}" for name, record in sorted(copied.items())))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"collect_runtime_libs: {error}", file=sys.stderr)
        raise SystemExit(2)
