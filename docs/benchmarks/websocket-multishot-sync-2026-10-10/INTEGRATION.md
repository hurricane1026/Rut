# Integration validation

Integrated with main 2727c637 and the workload/verified tcpkali2 tooling branch.
Preserved current main's HTTP relay scheduling and CI toolchain fixes. All
WebSocket strategy experiments and offline policy overrides remain opt-in.

- Release rut, rut-compile, converter and relevant test binaries rebuilt.
- Full test_network, test_splice, test_frontend, test_cli_backend,
  test_workload_handler and test_ws_tunnel_iouring CTests passed.
- After naming/include fixes, network, splice, CLI, workload and WebSocket
  CTests passed again; focused frontend workload tests passed (2 / 19 checks).
- 40 benchmark-tool Python tests and 21 vendored tcpkali2 Rust tests passed.
- Changed C++ files pass clang-format 22; changed-line clang-tidy 22 on main,
  parser, analyzer, backend and native WebSocket test translation units is clean.
  Existing unrelated warnings are filtered; this is not a full CI tidy claim.
- Full remote CI, sanitizer and macOS validation remain pending.

Performance tables describe the archived frozen study binaries, not a new
measurement of this integration head. No default-path performance win is claimed.
