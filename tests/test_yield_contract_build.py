"""Check that the production compiler gate rejects deliberate contract faults."""

from pathlib import Path
import os
import subprocess
import sys
import tempfile


def mutate(include, overlay, header, before, after):
    source = (include / header).read_text()
    if source.count(before) != 1:
        raise RuntimeError(f"Update the mutation for {header}")
    path = overlay / header
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source.replace(before, after))
    return path


def check(compiler, root, overlay, diagnostic=None, source="src/compiler/handler_verifier.cc"):
    command = [compiler, "-std=c++23", "-fsyntax-only", "-I", str(overlay),
               "-I", str(root / "include"), str(root / source)]
    # A new shadow header must invalidate the positive control on every run.
    result = subprocess.run(command, capture_output=True, text=True,
                            env={**os.environ, "LC_ALL": "C", "CCACHE_DISABLE": "1"})
    if diagnostic is None:
        if result.returncode:
            raise RuntimeError(result.stderr)
    elif result.returncode == 0 or diagnostic not in result.stderr:
        raise RuntimeError(f"Expected compilation to fail with {diagnostic!r}\n{result.stderr}")


def check_timer_transport(compiler, root, overlay):
    source = "src/runtime/response_read_timer_transport.cc"
    header = "rut/runtime/io_event.h"
    check(compiler, root, overlay, source=source)
    for before, after, diagnostic in [
        ("event.result == -ENOENT", "event.result == -ETIME", "Response timer result domain mismatch"),
        ("event.copy_end == 0 && ", "", "Response timer accepts unrelated event metadata"),
        ("u8 provided_ring_empty = 0;", "u8 provided_ring_empty = 0;\n    u8 new_field = 0;",
         "names"),  # Both compilers report the mismatch in the number of binding names.
    ]:
        probe = mutate(root / "include", overlay, header, before, after)
        check(compiler, root, overlay, diagnostic, source=source)
        probe.unlink()


def main():
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory() as directory:
        overlay = Path(directory)
        compiler = sys.argv[1]
        check_timer_transport(compiler, root, overlay)
        check(compiler, root, overlay)
        probe = mutate(root / "include", overlay, "rut/jit/handler_abi.h",
                       "enum class YieldKind : u8 {",
                       "enum class YieldKind : u8 {\n    UndeclaredContractProbe = 255,")
        check(compiler, root, overlay, "UndeclaredContractProbe")
        probe.unlink()
        probe = mutate(root / "include", overlay, "rut/jit/yield_contract.h",
                       "return {DownstreamSend, None};", "return {DownstreamRecv, None};")
        check(compiler, root, overlay, "Yield contract disagrees with RIR wait arms")
        probe.unlink()

        runtime = "src/runtime/jit_dispatch.cc"
        check(compiler, root, overlay, source=runtime)
        header = "rut/runtime/jit_dispatch.h"
        mutate(root / "include", overlay, header,
               "return jit::YieldKind::Recv;", "return jit::YieldKind::Send;")
        check(compiler, root, overlay, "Event eligibility disagrees with handler completion contract",
              source=runtime)
        # Replacing the overlay starts each mutation from the original header.
        mutate(root / "include", overlay, header,
               "return contract.secondary == jit::YieldArm::Timer;", "return false;")
        check(compiler, root, overlay, "Event eligibility disagrees with handler completion contract",
              source=runtime)
        (overlay / header).unlink()
        mutate(root / "include", overlay, "rut/runtime/io_event.h",
               "    Count,\n};", "    Count,\n    UnclassifiedEvent = 254,\n};")
        check(compiler, root, overlay, "UnclassifiedEvent", source=runtime)


if __name__ == "__main__":
    main()
