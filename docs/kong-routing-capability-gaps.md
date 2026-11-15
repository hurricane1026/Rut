# Kong routing capability coverage

Audit base: `a3fe7f77de60d778ccbab68016a62277f88347c9` (2026-11-15).
Tracking issue: [#1098](https://github.com/hurricane1026/Rut/issues/1098).
Implementation branch: `feat/kong-routing-coverage`.

The ten audited configuration intents now have native Rut implementations and
positive executable witnesses. Existing default routing and clean-prefix
restrictions remain explicit legacy controls; their rejection tests do not
represent open gaps when the corresponding opt-in API is used. This ledger
covers these routing capabilities, not every Kong plugin or API.

## Reproduce

```sh
cmake --build build --target rut test_frontend test_network test_routing_properties test_target_transform
ctest --test-dir build -L 'kong-gap|routing-capability' --output-on-failure --no-tests=error -j2
ctest --test-dir build -R '^test_kong_differential_' --output-on-failure
```

The frontend ledger traverses parsing, analysis, MIR/RIR and verification.
Deterministic network witnesses cover guard, capacity, cleanup and ownership
paths. `test_routing_capabilities.py` observes real upstream traffic over both
epoll and io_uring, H1/H2 and cleartext/TLS. The separate pinned Kong 3.9.1
baseline retains its documented equivalences and known differences.

## Completed capability ledger

| Configuration intent | Native Rut API / positive witness | Explicit bounds |
| --- | --- | --- |
| Runtime-computed upstream target | `set_path: expression`; capture/local/header-backed concatenations reach the upstream | Validated origin form, 8192 bytes, owned request Arena copy |
| Non-slash byte-prefix stripping | `target_transform: { strip_prefix: "/catalog", replace_prefix: "/", mode: .rawPrefix }` produces `/ue` from `/catalogue` | 128-byte prefixes, 16 transform profiles |
| Regex capture results | `regexCapture(req.pathOnly, re"^/v([0-9]+)/users/(.*)$", 1): str?`; captured strings build a forwarding target | Literal pattern 1024 bytes, 8 groups, input 8192 bytes; resource errors return 500 before guard recovery |
| Consistent normalized selection and forwarding | Guard `req.normalizedPath` and `req.normalizedTarget`, select on the former, forward the latter | Opt-in; query bytes remain opaque; raw route dispatch unchanged |
| Actual connection metadata | `req.sni`, `req.remotePort`, `req.localPort`, `req.isTls` | SNI at most 253 bytes, client-selected rather than authenticated; headers and H2 :scheme cannot replace transport state |
| Independent Host policies | `@host("a.example")` / `@host("b.example")` on identical method/path, separate chains and rate namespaces | 16 scopes / 128 total routes; exact, edge wildcard, global fallback |
| Preserve Host plus prefix rewrite | Existing `.preserve` request profile composed with explicit `.rawPrefix` | Existing closed request-policy profile remains explicit |
| After-response headers plus prefix rewrite | Borrowed original-path response header survives explicit rewrite | Stabilize borrowed values; invalidate replay of the old raw snapshot |
| Body / explicit CL0 plus prefix rewrite | POST payload and GET CL0 survive rewriting; H1 headers reach upstream before delayed body | H1 streams; H2 uses existing 16 KiB total synth bound |
| TLS/H2 plus prefix rewrite | All eight real transport profiles | Oversize/invalid/cancelled requests retain fail-closed protocol behavior |

The old `.match(re"...")` spelling remains absent; `regexCapture` is a native
Rut domain builtin, not an approximate Swift `Regex.Match` type. Optional
captures distinguish no match/unparticipating group from a participating empty
string. Group 0 is the whole first match; groups 1...8 are capture ordinals.

## Capture backend decision

The initial ledger preferred one regex engine. Inspection confirmed that
[Vectorscan/Hyperscan does not return capturing subexpressions](https://intel.github.io/hyperscan/dev-reference/compilation.html).
A second bounded C backend is therefore necessary for accurate greedy,
alternative, optional and nested captures; approximating them through repeated
Boolean scans would change results. [PCRE2 10.49](https://github.com/PCRE2Project/pcre2/releases/tag/pcre2-10.49)
is pinned by SHA-256 and built statically, with JIT/Unicode/tools disabled.
Existing Vectorscan Boolean operations retain their backend and fast path.
The pinned distribution licence is retained in [pcre2-LICENCE.md](third-party/pcre2-LICENCE.md).

The tradeoff is one maintained dependency and an additional static archive
(332 KiB in this build). Capture programs own a bounded 1 MiB mmap region;
matching uses request Arena callbacks, at most 64 KiB cumulative allocation per
call, a 12 KiB frame-vector heap limit, depth 64 and 100000 matching steps.
The frame-vector limit fits existing 16 KiB slices. It can reject a complex
otherwise-valid match: this is a resource error, never an absent capture.
PCRE2's [match/depth/heap limits](https://www.pcre.org/current/doc/html/pcre2pattern.html)
are enforced without the PCRE JIT. Native artifacts store the bounded pattern and
recompile at startup; execution never compiles a request-supplied pattern.

The following sections preserve the original audit and staged validation history.

## Original audit validation (2026-11-15)

Linux, Clang Release, JIT enabled, project-pinned OpenSSL and Vectorscan:

- `ctest --test-dir build -L kong-gap --output-on-failure --no-tests=error`:
  2/2 CTest entries passed; 8 frontend cases / 27 checks and 5 runtime cases /
  107 checks passed (13 cases, 134 checks total).
- Related frontend filter
  `target_transform,request_policy_preserve_host,req_path_regex,analyze_rejects_duplicate_route_keys`:
  16 cases / 329 checks passed.
- Related network filter `target_transform`: 14 cases / 711 checks passed.
- Changed `.inc` files pass `clang-format --dry-run --Werror`; `git diff --check`
  passes.

No live Kong differential, epoll/io_uring matrix or sanitizer suite was run for
this test-only characterization change. No production runtime or language
semantics were changed.

The full clang-analyzer pass over the existing large test translation units was
stopped after several minutes; it is not recorded as passing.
Scoped clang-tidy with analyzer checks excluded found fixture-only enum linkage,
enum size and constant naming diagnostics; these were corrected. The frontend
include's non-analyzer checks and the runtime include's final identifier-naming
check completed without diagnostics in the changed files. Existing diagnostics
outside the line filters are not claimed clean.

## Implementation progress

- Runtime-computed `set_path` targets are implemented for ordinary request
  expression scopes, including locals, direct concatenation and if branches.
  Literal targets retain their fast path. Optional/non-string operands reject;
  owned RIR effects are verified, and borrowed nonconstant targets reject.
- Target validation rejects invalid origin-form bytes before upstream contact;
  request Arena ownership preserves header-backed targets through buffer growth.
- Real two-shard epoll and io_uring witnesses each passed nine requests covering
  captures, growing/shrinking header-backed targets, POST body forwarding,
  keepalive state reset and four invalid-target refusals. Registered as
  `test_routing_capabilities_epoll` / `test_routing_capabilities_io_uring`.
- Focused validation: 23 frontend tests / 332 checks; owned-target helper 1 / 8;
  target-transform and target validation 16 / 197; both live backends passed.
  These results replace the first rejection witness, not the other open items.

### Explicit general prefix profiles

`.rawPrefix` / `.normalizedPrefix` now provide positive witnesses for byte-prefix
stripping, Host preservation, chain-after headers, body forwarding and TLS/H2
transport. The old rejection tests are named `legacy_clean_*` and continue to
protect the default profile's existing semantics. General modes are an explicit
native Rut option, not a changed meaning for old configurations.

The live matrix has eight combinations: epoll/io_uring, HTTP/1/HTTP/2 and
cleartext/TLS. It observes actual upstream targets and bodies, an original-path
response header, preserved Host, streamed HTTP/1 headers before the client body,
HTTP/2 timer continuation and reset/length-error reuse with no aborted upstream
request. HTTP/2 body forwarding uses the existing 16 KiB synth bound. URI
normalization has independent idempotence and in-place vectors. Capacity failures
leave input bytes unchanged and release Arena slices on close; borrowed response
values survive rewriting and the old raw snapshot is made non-replayable.

General forwarding normalization is implemented; explicit normalized route
selection and the remaining connection/capture/host-scope items are still open.

Validated on 2026-11-15: all eight live CTest profiles passed (126 requests),
both `kong-gap` entries passed; focused frontend 24 tests / 335 checks, network
22 tests / 887 checks, target/normalizer 19 tests / 277 checks. No sanitizer run
is claimed for this stage. Standalone normalizer header clang-tidy completed;
existing naming diagnostics in the older transform header remain outside the
changed lines.

### Explicit normalized selection and connection metadata

`req.normalizedPath` / `req.normalizedTarget` are optional request-owned strings;
root route predicates can select on the former and forward the latter. The live
matrix verifies `/api/../admin`, encoded unreserved bytes and repeated slashes
select and reach the corresponding normalized target while retaining query bytes.
`req.sni`, `req.remotePort`, `req.localPort` and `req.isTls` use connection state.
Forged SNI/Forwarded headers and H2 :scheme cannot replace transport state.
SNI is routing input, not authenticated identity. Slot reuse clears fixed storage.

Validation: 11 frontend gap tests / 44 checks; 2 helper tests / 19 checks;
all eight live profiles passed with four additional probes per profile (158
requests total). RIR admission validates selector and result types. No sanitizer
or macOS/kqueue execution was performed for this stage.

### Independent Host scopes

`@host("a.example")` and `@host("b.example")` now attach independent handlers,
chains and decorators to the same method/path. Exact/wildcard/global precedence,
case/port handling and distinct rate-limit namespaces have positive witnesses.
Cold scope indexes are owned by RouteConfig and rebuilt after native load;
request lookup allocates nothing. The live matrix caught and fixed the native
relocation requirement that routes remain at config offset zero.

Validated: 13 gap frontend cases / 47 checks, 4 standalone property cases / 38
checks, all nine routing-capability CTest entries (eight live transports plus
unit suite). The Host static handlers have separate after-header policies. The
full legacy network suite and sanitizer are deferred to final combined checks.

### Final combined validation (2026-11-15)

All ten audited intents have positive witnesses. Normal Linux Clang Release,
JIT enabled, both real I/O backends, project-pinned OpenSSL/PCRE2:

- Full frontend: **1306 tests / 22905 checks**, all passed.
- Full network: **1666 tests / 495440 checks**, all passed under the default
  8 MiB stack. Eight older multi-config fixtures now hold their large configs
  on the heap; assertions and lifecycle coverage are unchanged.
- Target/normalizer: **19 / 277**; capture adapter **3 / 30**; transport/ownership/
  capture helper properties **8 / 72**, all passed.
- `kong-gap|routing-capability`: **12/12 CTest entries**. The final eight live
  profiles passed **254 requests**, including mixed Vectorscan/capture literals,
  named Host chains, scoped params across a timer, canonical IPv6 Host, valid
  non-DNS authority fallback, normalization, bodies, TLS, H2 reset/length errors
  and captured target rewriting. Missing Host retains global-route eligibility.
- Existing pinned Kong differentials: **2/2 entries**, retaining each backend's
  16 equivalences and 5 documented differences; no universal Kong parity claim.
- Existing regex/native-helper/target JIT regressions **17 / 10485**, loader
  **141 / 53995**, harness **56 / 417**, simulation **69 / 474**, ART **43 / 1416**
  and segment trie **39 / 4651**, all passed.
- LLVM-free Debug ASan+UBSan build: capture adapter **3 / 30**, gap frontend
  **15 / 63**, all passed with leak detection. A separate instrumented native
  helper/capture/property run (including instrumented PCRE2) passed **8 / 72**.
  This is targeted instrumentation, not a full sanitized live-backend matrix.
- Changed-file formatting and `git diff --check` passed. Scoped clang-tidy
  reported no diagnostics in the new Host helper or capture adapter; the
  existing const-correctness diagnostic in `arena.h` remains outside this change.
  The normal server's ELF dependencies contain only `libc.so.6`; the build's
  no-C++-stdlib dependency guard passed. Main remains the audited base commit.

The existing closed explicit `.preserve` request-header profile remains a
cleartext HTTP/1 capability. General prefix transforms support TLS/H2 but do not
broaden every legacy request-policy profile or every combination of policies.
H2 request forwarding retains its documented total 16 KiB synth bound; capture
resource exhaustion is an explicit 500. These limits are separate from the ten
configuration intents proved above.
