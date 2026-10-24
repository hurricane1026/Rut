# Envoy configuration helper

This standalone tool converts the supported subset of Envoy bootstrap JSON to
ordinary `.rut` source. It does not execute programs or implement HTTP behavior.
The Rut compiler and runtime implement every policy expressed by its output;
handwritten `.rut` programs have the same capabilities.

The `rut` executable and its compiler/runtime libraries do not depend on this
helper. Envoy JSON parsing and configuration models live only in this directory.
Unsupported configuration is rejected instead of silently approximated.

## Build independently

```sh
cmake -S helpers/envoy -B build-envoy-helper
cmake --build build-envoy-helper
build-envoy-helper/rut-envoy-convert bootstrap.json > gateway.rut
```

This build needs a C++23 toolchain and the repository headers, but no LLVM,
BoringSSL, gateway runtime, or external Envoy libraries. In a full repository
build the binary is `build/helpers/envoy/rut-envoy-convert`.

Run the emitted program separately with `build/src/rut gateway.rut`.
See [conversion scope](../../docs/envoy-converter.md) and the
[compatibility matrix](../../docs/envoy-compatibility.md) for remaining limits.

The supported IPv4 TCP addresses accept `protocol: "TCP"` or `protocol: 0`
explicitly, and clusters accept `lb_policy: "ROUND_ROBIN"` (also `lbPolicy`)
or integer `0`. These spell the existing defaults and emit the same Rut source
as omission. Other transports and load-balancing policies remain rejected.
