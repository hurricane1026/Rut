# simdjson allocator patch

Upstream: <https://github.com/simdjson/simdjson>

Pinned submodule: `third_party/simdjson`, tag `v5.0.5`, commit
`9c003534b1be3bc4f1322bfa7a770a7ffbf247d9`. The gitlink pins the commit;
there is no tracking branch or automatic update to upstream HEAD.

`0001-ondemand-allocator-hooks.patch` is maintained separately from the pristine
submodule. It adds opt-in allocation hooks for the explicit OnDemand parser's
string buffer, development-check stack, structural indexes, container stacks,
and internal implementation object. With `SIMDJSON_RUT_ALLOCATOR` undefined,
these paths retain upstream allocation behavior. The patch also checks string
and development-stack allocation failures explicitly and returns `MEMALLOC`.

This dependency is proposed for SIMD JSON parsing and validation. Rut does not yet use it as a JSON backend. The patch allows allocator
adaptation without globally replacing C++ allocation operators; retaining a small
versioned patch costs less than maintaining a separate parser fork.

## Applying the patch

Initialize the pinned dependency:

```bash
git submodule update --init third_party/simdjson
```

Apply to a separate source copy for a build, or explicitly to the submodule:

```bash
git -C third_party/simdjson apply --check ../../patches/simdjson/0001-ondemand-allocator-hooks.patch
git -C third_party/simdjson apply ../../patches/simdjson/0001-ondemand-allocator-hooks.patch
```

Applying in the submodule makes its worktree dirty by design. Do not commit the
patched files as a replacement upstream commit. The standalone check below
applies to a temporary copy and leaves the submodule untouched.

## Allocator contract

Compile all participating translation units with consistent definitions:

```text
SIMDJSON_RUT_ALLOCATOR=1
SIMDJSON_EXCEPTIONS=0
```

Leave `SIMDJSON_THREADS_ENABLED` undefined for this profile. The pinned
upstream headers use `#ifdef SIMDJSON_THREADS_ENABLED`, so defining it as `0`
still enables the threaded interface and behavior. They also define it when
`_REENTRANT` or `_MT` is set, so compile without `-pthread` or equivalent
thread-enabled flags. The standalone probe checks the macro after including
simdjson headers and fails to compile if either path enables threading.

The embedding application supplies:

```cpp
extern "C" void *simdjson_rut_allocate(size_t bytes, size_t alignment) noexcept;
extern "C" void simdjson_rut_deallocate(void *pointer) noexcept;
```

Allocation returns appropriately aligned storage or null on exhaustion. Storage
must remain valid until its matching deallocation. Deallocation must identify
the original owner from the pointer or persistent metadata, rather than the
currently selected thread-local arena. A monotonic arena may defer reclamation,
but must not reset before the parser and all borrowed values are destroyed.
Hooks are not changed at runtime. A shard-local parser must stay on its owner
shard. Preallocate with `parser.allocate(capacity, max_depth)` before requests,
and enforce input size limits so requests cannot trigger capacity growth.

## Verification

From the repository root, with Clang, standard shell utilities, Git,
`tar`, `rg`, and `readelf` available:

```bash
tests/simdjson/check_patch.sh
```

The check is also registered with CTest when configured with
`-DRUT_TEST_SIMDJSON_PATCH=ON` (Linux only; off by default).

Both development-check configurations (`0` and `1`) are tested.
The check verifies the pinned SHA and patch applicability, compiles the patched
modular sources with exceptions and RTTI disabled and `-nostdlib++`, parses
10,000 documents without further allocator calls, injects failure at each
initial allocation, checks recovery and matching deallocation, and inspects ELF
dependencies for `libstdc++` / `libc++`.

The probe supplies **test-only** C++ ABI stubs; unsupported ordinary allocation
paths abort rather than silently calling malloc. It also uses
`-fno-threadsafe-statics` for this single-threaded experiment. These choices are
not a production integration or a concurrency proof.

## Deliberate scope limits

- Only explicit OnDemand parser allocation paths are adapted. DOM document
  buffers, padded-string allocation, builders, stream workers, standard-library
  deserialization, and convenience thread-local parsers are not supported by
  this patch and must not be used under the Rut allocator profile.
- Upstream virtual dispatch remains. The patch does not yet satisfy Rut's
  prohibition on hot-path virtual dispatch.
- Standard-library headers remain; this is not a freestanding implementation.
  Remaining C++ ABI symbols and initialization must be addressed before linking
  into the production runtime. The probe's ABI stubs are not that solution.
- Input padding, complete JSON validation, numeric representation, duplicate-key
  policy, and borrowed-view lifetimes still need a Rut wrapper and tests.
- No CMake production target or Rut parser backend is switched by this change.

Upgrade the submodule SHA and patch together, then rerun this check and the
runtime's normal dependency and lifecycle validation. Do not use the upstream
checked-in singleheader amalgamation for testing this patch: regenerate it from
the patched modular source if an amalgamation is required.
