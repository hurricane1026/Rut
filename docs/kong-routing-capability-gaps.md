# Kong routing capability gap witnesses

Audit base: `a3fe7f77de60d778ccbab68016a62277f88347c9` (2026-11-15).
Tracking issue: [#1098](https://github.com/hurricane1026/Rut/issues/1098).
The goal is to express the same configuration intent in native Rut, not to import
Kong JSON, introduce Kong keywords, or silently change existing Rut semantics.

These are **current-behavior characterization tests**. A passing rejection test
confirms an open gap; it does not mean that the capability is implemented. When
implementing a capability, change its witness to positive acceptance and add
appropriate wire/lifecycle tests rather than retaining the old rejection.

## Reproduce

Use the normal Linux JIT-enabled CMake build and pinned project dependencies:

```sh
cmake --build build --target test_frontend test_network
ctest --test-dir build -L kong-gap --output-on-failure --no-tests=error
```

The label selects eight frontend tests and five deterministic runtime tests.
The frontend controls pass parsing, semantic analysis, MIR/RIR lowering and the
RIR verifier. The runtime witnesses exercise the production route matcher,
request-target materializer and, where specified, Forward refusal path using the
existing SmallLoop backend. No new test framework or dependency is introduced.

## Witness ledger

Every test below uses suite `kong_routing_gap`.

| Configuration intent | Witness name | Expected current observation |
| --- | --- | --- |
| Exact path, byte prefix, regex predicate, Host/header/query conditions and method union | `expression_routing_controls_reach_verified_rir` | Seven positive source controls reach verified RIR. These capabilities are not gaps. |
| `/users/:id` to `/internal/accounts/<id>` | `dynamic_captured_path_reaches_verified_rir` | Literal and computed `str` targets reach verified RIR; dynamic targets use a request-owned copy. Closed by the implementation progress below. |
| Strip the byte prefix `/catalog` from `/catalogue` | `legacy_clean_prefix_requires_slash_boundary` | `/catalog/` is accepted; the otherwise identical `/catalog` prefix is rejected. |
| Obtain regex captures for downstream policy/rewrite | `regex_capture_accessor_rejected_after_boolean_control` | `.matches(re"...")` works as a bool; the language-card target spelling `.match(re"...")` is rejected during parsing. This does not reject ordinary `:param` captures. |
| Route on actual SNI, source/destination port or TLS state | `connection_metadata_accessor_probes_are_not_http_fields` | `req.httpVersion` works; candidate `req.sni`, `req.remotePort`, `req.localPort`, `req.isTls` fields reject during analysis. These probes establish absence of these accessors, not absence of native transport metadata or every imaginable alternative spelling. The request-field inventory was separately inspected. Spoofable headers are not equivalent evidence. |
| Independent routes sharing method/path but differing by Host | `distinct_host_routes_collide_but_merged_branch_is_supported` | Separate declarations reject with `duplicate route path and method`; merged Host branching works. This is a route/policy organization limitation, not an inability to route by Host. |
| Preserve Host together with prefix rewrite | `legacy_preserve_host_rejects_clean_transform_combination` | The existing closed `.preserve` request policy works alone; adding the separately supported transform rejects during semantic analysis with `request_policy host: .preserve does not support this forward option`. |
| Prefix rewrite together with chain-after response headers | `legacy_clean_transform_rejects_after_headers` | After-header effect works alone; the transform combination rejects with its explicit semantic diagnostic. This does not assert that every other response policy is unsupported. |
| Ordinary prefix replacement, runtime suffix and repeated raw query keys | `clean_prefix_transform_preserves_runtime_suffix_and_raw_query` | Clean GET `/api/users?x=1&x=2` becomes `/v1/users?x=1&x=2`; bodyless POST without Content-Length also succeeds. |
| Normalize encoded unreserved bytes, repeated slash and dot segments before rewrite | `legacy_clean_profile_refuses_normalization_sensitive_targets` | Three targets reject unchanged, Forward returns 400, no upstream connection or held upstream slot. |
| Rewrite a POST with a body, or a GET with explicit Content-Length: 0 | `legacy_clean_profile_refuses_body_and_explicit_length` | Both reject unchanged and return 400 without upstream connection. POST method alone is not the restriction. |
| Prefix transform on TLS / HTTP/2 | `legacy_clean_profile_refuses_tls_and_h2_materialization` | Production materializer rejects both connection flags without buffer changes or I/O. This is a metadata-level guard witness, not a live TLS handshake/H2 stream test. |
| Normalized selection of routes and associated policies | `dispatch_does_not_normalize_dot_segments_or_unreserved_escapes` | `/admin` and `/api/users` select their specific routes; `/api/../admin`, `/api/%75sers`, `/api//users` select `/api`. There is no normalization-to-policy equivalence in this matcher. |

Both successful clean-prefix source controls and runtime controls are retained so
that unrelated parser, configuration or fixture failures cannot masquerade as a
gap. Negative runtime witnesses preserve the input buffer, header boundary and
initial send length, and check refusal before upstream Connect.

## Scope and follow-up

The existing [Kong differential baseline](kong-compatibility-baseline.md) is a
separate pinned Kong 3.9.1 comparison with known differences. These new tests do
not launch Kong, Docker, epoll or io_uring, and do not claim live wire equivalence.
They make local capability boundaries repeatable and cheap to diagnose.

Kong reference semantics: [Routes](https://developer.konghq.com/gateway/entities/route/)
and [traditional routing](https://developer.konghq.com/gateway/routing/traditional/).
Kong supports path stripping, normalized matching/forwarding and regex captures;
Rut may expose equivalent intent through its own existing syntax and APIs.

Recommended implementation order: runtime-computed safe forwarding targets;
request-body and transport support plus policy composition; explicit
normalization/matching/forwarding contracts; capture results and trusted
connection metadata. Keep route grouping/priority organization separate from
plain predicate expressibility. Do not add arbitrary keywords or another regex
library to satisfy this ledger.

## Recorded validation (2026-11-15)

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
