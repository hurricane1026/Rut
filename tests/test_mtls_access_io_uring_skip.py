#!/usr/bin/env python3
"""Verify the access-profile fixture translates only the real unavailable diagnostic to skip."""
import argparse
from pathlib import Path
import tempfile

from test_mtls_access_token_binding import gateway


def run_case(args, message, expected, backend="io_uring"):
    with tempfile.TemporaryDirectory(prefix="rut-mtls-uring-skip-") as tmp:
        fake = Path(tmp) / "fake-rut"
        fake.write_text("#!/bin/sh\nprintf '%s\\n' '" + message + "'\nexit 1\n")
        fake.chmod(0o700)
        args.server = str(fake)
        args.backend = backend
        try:
            with gateway(args, {}, "mtls"):
                raise AssertionError("fake gateway unexpectedly started")
        except SystemExit as error:
            assert expected == 77 and error.code == 77, error.code
        except AssertionError as error:
            assert expected == "startup-error" and message in str(error), str(error)
        else:
            raise AssertionError("startup condition was not reported")


def main(testdata):
    args = argparse.Namespace(
        server="", source=str(Path(__file__).resolve().parent.parent /
                              "examples/mtls-access-bound-rs256-auth.rut"),
        testdata=testdata,
        backend="io_uring", algorithm="rs256", opt=2)
    run_case(args, "--backend io_uring requested, but io_uring is unavailable", 77)
    run_case(args, "--backend io_uring requested, but io_uring is unavailable",
             "startup-error", backend="epoll")
    run_case(args, "unrelated compiler startup failure", "startup-error")
    print("PASS: io_uring unavailable skips only the exact diagnostic despite exit 1")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--testdata", required=True)
    main(parser.parse_args().testdata)
