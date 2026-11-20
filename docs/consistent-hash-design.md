# Consistent Hashing for Upstream Selection

Status: **implemented with the validation boundaries recorded below**. This
specification includes deployment acceptance criteria beyond the local test suite.
Design baseline: `388fc48ba`; scenarios K017/K018. The compiler accepts
`.roundRobin`, `.leastRequests` and `.consistentHash`. See the [language card](language-card.md#explicit-load-balancing-at-each-forward-call).

## 1. Goals and scope

Add a third policy that selects upstream targets consistently by request key,
with existing 0–65535 weights, zero-weight disablement, health ejection, capacity
thresholds, retries and configuration RCU. Given the same key, seed, target
identities and weights, eligible set and algorithm version, selection must agree
across shards, processes, I/O backends, compilers and supported architectures.
Selection must not depend on arrival order, connection-pool hits, active request
counts or load-balancing call-site numbers.

Consistency means limiting remapping when the target set changes. It does not
promise identical health observations across nodes or persistent sessions.
Requests can move after a target goes down; established WebSocket, SSE and gRPC
streams do not migrate.

The first release covers up to eight static IPv4:port targets with all existing
weights. Ordinary HTTP forwarding and native gRPC forwarding must pass acceptance
on epoll/io_uring and JIT/Native artifacts. Enable WebSocket only after verifying
that handshake forwarding uses the same key and selection path, with separate
tests. Until integrated, reject that combination at compile time rather than
falling back to round-robin. Explicit `wait(upstream(...).connect())` keeps its
current contract and gains no hash arguments. DNS-driven targets, Target management
APIs, automatic Cookie issuance and Kong configuration import are outside this scope.

## 2. Proposed Rut interface

The following is a **future compiler interface**, not a runnable example today:

```swift
upstream api {
    backends: ["10.0.0.1:8080": 3, "10.0.0.2:8080": 1]
    minimum_healthy_weight_percent: 1
}
route GET "/orders" {
    guard let tenant = req.uniqueHeader("X-Tenant-ID") else { return 400 }
    return forward(api, load_balance: .consistentHash,
                   hash_key: tenant, hash_seed: env("UPSTREAM_HASH_SEED"))
}
```

- Reuse member values, labelled call arguments and existing expression syntax.
  Add no keywords or external libraries. `.consistentHash` is a policy enum member;
  `hash_key` and `hash_seed` are ordinary argument labels.
- Accept these two arguments only with `.consistentHash`. Both are required and
  each may appear once. Reject arguments on other policies, missing or duplicate
  arguments and unknown members at compile time. Infer no upstream default policy.
- `hash_key` accepts a non-optional `str` or `IP`, evaluated exactly once. Initially,
  accept only the existing pure-expression subset: literals, bound locals, scalar
  request reads and verified pure helpers. Reject waits/I/O, state mutation and
  calls whose purity cannot be established. Add no implicit authentication,
  request attributes or arbitrary user-object serialization.
- `str` means exact bytes, including NUL, with a length of 1–4096 bytes. Empty or
  oversized keys produce 400 before opening a connection, acquiring upstream
  capacity or incrementing an active count. Do not truncate, select randomly or
  implicitly use round-robin. Reject known invalid constants at compile time;
  validate dynamic values at runtime. Native gRPC maps invalid keys to an HTTP 200
  trailers-only response with `grpc-status: 3` (INVALID_ARGUMENT), and internal
  digest/configuration unavailability to `grpc-status: 14` (UNAVAILABLE). Reuse
  existing response ownership; reject the combination until this mapping exists.
- `IP` initially accepts the runtime's existing IPv4 type, encoded as four bytes
  in network order. Future IPv6 support needs an explicit family tag and 16-byte
  encoding. An IP and its textual string representation have distinct type tags.
- `hash_seed` is a compile/load-time constant string of exactly 32 lowercase hex
  characters, decoded to 16 bytes; all-zero seeds are invalid. Environment values
  use existing compile/load-time `env()`, never request input. Instances requiring
  the same mapping must share the seed. Changing it deliberately remaps the key
  space. Provide no random per-process default. Never log or label metrics with
  the seed, request key or key digest.

Rut code handles key sources explicitly. Prefer `uniqueHeader` for headers and
reject missing or duplicate values. Query/Cookie sources retain their accessors'
existing first-value/raw-byte rules; they do not claim duplicate detection.
Strict uniqueness requires a unique-value accessor or explicit validation first.
An authenticated Consumer ID can be a key only after authentication; a client
asserting an ID does not authenticate it. `req.remoteAddr` is the peer address
established by the trust boundary, not an implicitly trusted `X-Forwarded-For`.
Missing-key fallback can explicitly select another forward in an existing `match`
branch; the hash selector must not hide a fallback.

Evaluate the key when its forward executes, against the existing logical request
view before forwarding rewrites. Existing upstream `req.set/remove` mutations
must not silently alter original-request reads. All subsequent retries reuse
that evaluation; never re-read a mutable raw request buffer.

## 3. Algorithm choice

Use **weighted Rendezvous / HRW (Highest Random Weight)** in exponential-race
form. Compute one independent score per target and choose the smallest
`-log2(U) / weight`. Under an ideal continuous random model, a target's share is
`weight / sum(weights)`. The implementation uses the bounded integer approximation
below. Validate distribution statistically; promise neither exact finite-sample
ratios nor the absence of quantization error.

| Option | Tradeoff |
| --- | --- |
| `hash % count` / cumulative-weight modulo | Target-set changes remap many keys; fails the consistency goal |
| Ketama virtual-node ring | Viable, but finite-point weight precision, ring memory and rebuild rules add complexity; point-for-point Kong compatibility is not a first-release goal |
| Maglev lookup table | Useful for fast lookup in large pools; construction and resident-memory costs offer less benefit with at most eight targets |
| Weighted HRW | O(N), no ring or mutable scheduling state, and declaration reordering preserves mappings; fits the bounded small pool |

### 3.1 Stable identity and digest encoding

A target identity is exactly seven bytes: `0x04 || IPv4[4] || port_u16_be`.
Do not use raw structure memory, address text, declaration indexes, upstream
names, site IDs, shard IDs or RCU generations. Reject duplicate identities in
source configuration, hand-built RouteConfig and the Native loader; names must
not turn one endpoint into two targets. Ports are 1–65535. Shared encoding
helpers must define byte order, lengths and comparison rules.
The same endpoint in different upstreams/forwards receives the same score for
the same seed and key. Use different seeds or explicitly namespaced business
keys when independent mappings are required.

Reuse the [raw digest interface](../include/rut/runtime/hash.h), rather than a
Rut builtin returning a hex string:

```text
key_frame = "rut-lb-key-v1" || type_u8 || key_length_u32_be || key_bytes
D = HMAC-SHA256(seed[16], key_frame)               # retain all 32 bytes
H(endpoint) = SHA256("rut-lb-hrw-v1" || D[32] || endpoint_id[7])
h = max(1, big_endian_u64(H[0:8]))
```

Domain separators are the ASCII bytes shown, without trailing NUL; type is
str=1 or IPv4=2. Use `hash_digest_parts` to avoid concatenating large keys.
Temporary digests use stack scratch, input reads are bounded and no third-party
dependency is needed. Digest failure returns local 503 without marking a target
unhealthy or switching to round-robin.
HMAC reduces offline target prediction when the seed is unknown; it replaces
neither authentication nor hotspot rate limiting. Public/leaked seeds, online
probing, low-cardinality keys and individual hot keys can still cause severe skew.

### 3.2 Deterministic integer scores

Do not use hot-path `double`, `log()`, platform libm, floating-point fast-math
or random runtime salts. Define `cost(h)` with this Q32.32 negative-log
approximation; all shifts and multiplication are unsigned:

```text
n = floor(log2(h))                 # highest set-bit index of nonzero u64, 0..63
x = u128(h) << (63 - n)            # Q1.63, 2^63 <= x < 2^64
fraction = 0u64
for j in 1..32:
    y = (x * x) >> 63             # x*x < 2^128; y can require 65 bits
    if y >= 2^64:
        y = y >> 1
        fraction |= 1u64 << (32 - j)
    x = y                         # remains in [2^63, 2^64)
cost = ((64 - n) << 32) - fraction
```

Compute `floor(log2(h))` with integer bit operations, not a logarithm library.
Keep `x/y` as u128; do not truncate to u64 before normalization. Low-bit
truncation after each square and the normalization order are part of the
algorithm; a different precision is not interchangeable.
`cost` lies in 1..`64 * 2^32`. Compare targets a/b using `cost_a * weight_b`
and `cost_b * weight_a`; both fit u64 (less than 2^54). Do not divide first.
Break exact ties by the smaller endpoint_id in unsigned-byte lexicographic
order, never a round-robin cursor or declaration order.

Name this version `rut-hrw-sha256-q32-v1`. Changes to hashing, encoding, precision
or tie-breaking can migrate keys and require a new version with an explicit
migration contract. Compiler build IDs or Native artifact upgrades must not
silently change mappings. The first release exposes no algorithm-version
argument. Configuration diagnostics/publication previews should show the version;
define a migration interface before shipping a later algorithm version.

### 3.3 Guaranteed remapping boundaries

Scores are independent when unchanged targets retain their identities and
weights, and the seed and key remain fixed. Therefore:

- Adding one target moves keys only from their original winner to the new target.
- Removing/disabling one target leaves keys owned by other targets unchanged;
  restoring it can move keys only to the restored target.
- Increasing one target's weight moves keys only toward it; decreasing its
  weight moves keys only away from it.
- Reordering declarations, recompiling, renumbering sites/shards or changing
  unrelated configuration preserves mappings.

Changing several targets, the key, seed or endpoint identity is outside these
single-target guarantees. Measure distribution over many distinct keys. A million
requests with one key must continue selecting one target; those requests cannot
be used to claim that 3:1 distribution failed. Cross-node agreement also requires
the same eligible set and health observations.

## 4. Health, capacity and retries

Reuse `select_forward_backend` gates rather than creating a second health table.
Retain existing caller-side health-configuration generation validation, request
admission and route/protocol checks. An old snapshot's indexes must not read
health values belonging to a replacement configuration.

1. Validate context, configuration, policy and request key. Weight zero is
   always ineligible.
2. Evaluate `minimum_healthy_weight_percent` across all configured enabled
   targets. Retry exclusions must not shrink its denominator. Return 503 before
   connecting if the capacity threshold is unmet.
3. Positive thresholds allow healthy targets only. Threshold zero retains
   existing behavior: skip unhealthy targets when a healthy unattempted target
   remains; otherwise allow fail-open to remaining enabled targets.
4. Select by HRW score among eligible targets. Reuse existing capacity
   acquisition/release paths. Selection failure must not invent an upstream
   failure or release capacity that was never acquired.

Health changes update only the candidate mask, not identities/scores, a ring
or other targets' scheduling credits. After recovery, new requests return to
their original preferred target. Established streams do not migrate, and affinity
to an unhealthy target is not promised. Nodes can observe different health,
so selection across nodes during failures is not guaranteed to agree.

Retry order follows the same key's score ranking, filtered by current health,
capacity and previously attempted targets. Reuse the existing backend exclusion
bitmask (up to eight bits), retry eligibility, attempt limits and deadlines.
Affinity must not justify retrying a transmitted non-idempotent request, an
already committed streaming response or the same failed target. Re-evaluate
health only for unattempted targets; it may change between attempts. With stable
health, retry order is deterministic. Pools may reuse only the selected target's
connection; an idle connection must not override hash selection.

## 5. Compiler, JIT, Native and ownership

Follow the existing compilation chain. Structure names may change, but every
layer must preserve metadata and validate it strictly:

| Layer | Change |
| --- | --- |
| `common/load_balance.h` | Policy enum and strict validity checks; algorithm version, key carrier and policy definitions |
| AST → HIR → MIR → RIR | Preserve key expression/type, seed-policy reference and site identity; explicit lowering without string-label shortcuts around type checking |
| JIT helpers / outcome | Evaluate once and digest before forward; preserve request-owned values across suspend/resume |
| RouteConfig / Native metadata | Immutable seed/version table for up to 512 sites; validate indexes, constant lengths and policy combinations on load |
| HTTP/1 connection, HTTP/2 stream / gRPC context | Store D[32] and an explicit valid flag; neither connection/shard IDs nor a single shared H2 connection key can substitute for per-request keys |
| Runtime selector | One bounded HRW helper integrated through existing templates/branches on both backends; preserve existing policies |

Keep the key digest in request/stream-owned storage. Do not retain borrowed
`Str` values for retries. Bind digest and policy to the pinned request
configuration epoch; old requests cannot use a new seed, and existing active
gauges are released in the original configuration. Clear validity and digest
on the next request, H2 RST/END_STREAM, JIT error returns, cancellation and close.
Test context reuse explicitly rather than relying on default zero initialization.

Own the immutable policy table through the configuration Arena/existing owner.
Budget up to 512×32=16 KiB of entries (16-byte seed, version/flags and padding,
excluding existing expression IR), allocated on demand during configuration only.
Budget a 32-byte digest plus flags/policy reference per request, expected to fit
within 48 bytes per active request. Measure padding growth separately in
Connection, H2 stream and outcome; do not omit costs by counting them together.
Do not copy seeds into mutable per-shard/site state or add a 64×512×8 score array.

Initial selection processes at most 4096 key bytes, eight target digests and
256 integer squarings. A retry can recompute at most eight target scores without
allocation or sorting; existing attempt limits bound total work per request.
Caching rankings requires separate storage/cleanup evidence and is not assumed.
Keep `rut_runtime` LLVM-free. Reuse pinned OpenSSL and compiler integer support;
add no libm, C++ standard library, ordinary heap allocation, virtual dispatch,
coroutines or cross-shard synchronization.

When metadata/request ABI changes are implemented, bump the Native artifact
version to **the then-current version +1**. Do not freeze an integer in this
proposal or change artifacts prematurely. Reject old artifacts with a recompilation
diagnostic; malformed/forged policies must not silently fall back.
Hand-built embedded RouteConfig values also require validated hash policies;
the compiler cannot be relied on to supply defaults for them.

## 6. Kong comparison boundaries

Kong documents Ketama-based consistent hashing with Consumer/IP/Header/Cookie
inputs, fallback for some sources and health-based target skipping without
changing the hash layout. See [Upstreams: consistent-hashing](https://developer.konghq.com/gateway/entities/upstream/#consistent-hashing).

This design covers explicit-key affinity, weighting, limited remapping after
target changes and healthy-target substitution. It uses HRW, so identical keys
need not select the same endpoint in Kong and Rut; neither per-request nor
per-weight mapping identity is promised. Automatic Cookie generation and
sticky-sessions are separate capabilities outside this proposal.

Differentials must use the repository's pinned [Kong image digest](../tests/pinned-kong-image.txt)
and [comparison baseline](kong-compatibility-baseline.md), not a moving documentation
version. At implementation time, verify that version's hash_on, weights and
health parameters. Claim coverage only for versions actually tested. Compare
stability, enable/disable behavior, remapping properties and distribution;
do not describe differing endpoint sequences as identical mappings.
The optional `--kong` mode of `tests/test_consistent_hash.py` runs that pinned
image. It checks header affinity, weighted distribution, zero-weight disablement
and reordering. Adding a target also records migrations between old targets:
Kong Ketama and Rut HRW have different placement and remapping behavior. See the
[validation record](consistent-hash-validation.md) for observed results.

## 7. Implementation stages and acceptance gates

| Stage | Deliverables and required evidence |
| --- | --- |
| A: pure algorithm | Stable encoding, HMAC/SHA256 and integer-score helpers; golden vectors, boundaries and ties; no exposed DSL yet |
| B: language and storage | Complete compiler chain, single evaluation, context ownership and Native validation/version; reject unknown policies and invalid combinations |
| C: real data plane | HTTP/1, HTTP/2, gRPC and both I/O backends; health, retries, capacity, pooling, RCU, cancellation and reclamation; mark supported syntax in the language card |
| D: compatibility and performance | Pinned Kong behavior differentials, distribution/remapping reports and performance data; explicitly reject WebSocket until accepted |

Merging A/B does not complete a usable feature. Mark the K018 subset complete
only after all C/D gates pass. Implementation PRs must update DESIGN, the
language card, examples and scenario index. Remaining deployment gates are recorded
explicitly in the validation record; this implementation does not claim all gates complete.

Required tests:

- Golden vectors: compare an independent integer reference implementation with
  C++ byte for byte, covering key_frame, D, H, h, cost and winner. Include h=0
  (clamped to 1), 1, powers of two, maximum u64/weight and ties. Require identical
  x86_64/arm64, Clang/GCC and Debug/Release/Native results. Reusing the helper
  under test as its own oracle is not independent validation.
- Stability/remapping: use a fixed public seed and at least 100,000 deterministic
  distinct keys with 1–8 targets. Check all reorderings and single-target
  add/remove, zero weight, recovery and weight increases/decreases; distribution
  alone is insufficient.
- Distribution: equal weights, 3:1, 1:65535 and mixed eight-target pools. Use
  explicit binomial/multinomial tolerances with a fixed corpus. Rare targets may
  receive zero samples; a fixed relative-error requirement is inappropriate for
  extreme weights. Freeze statistical criteria before implementation.
- Keys: missing/duplicate headers, empty keys, 4096/4097-byte boundaries, binary
  NUL, IP families/type separation, explicit missing-key fallback, authentication
  ordering, request-rewrite views, invalid seeds and purity rejection. Invalid
  keys must never contact upstreams.
- Ownership: H1 keepalive/pipelining on both backends, concurrent H2 streams with
  different keys and RST, gRPC trailers/cancellation, partial send/receive, SQ
  pressure, timeout and Native execution after source removal. Acquire/release
  each attempt's active count exactly once.
- Reload: old requests retain their snapshot through seed/weight changes and
  target reordering, and release only old counters. New requests preserve mapping
  after an equivalent reload. Record migration from changed health separately;
  do not attribute it to algorithm drift.
- Health: positive capacity-threshold 503, default fail-open, no reactivation of
  zero-weight targets, retry exclusions preserving the threshold denominator,
  all targets unavailable, recovery and stable selection across forward sites
  sharing an upstream.
- Performance: run benchmarks separately on demand. Compare existing policies
  and HRW at 1/2/8 targets with short/4 KiB keys, reporting cycles, throughput and
  p50/p99 for initial selection, retries and concurrent H2. Do not introduce
  per-process random salts to pass benchmarks. Record existing baselines and
  acceptance thresholds before measurement; invent no current performance
  promise. Keep benchmarks out of default per-PR CI.
- Resources: ASan/UBSan, key isolation after request reuse, no-C++-runtime/ELF
  dependency checks, measured structure sizes and resident configuration memory.
  Cold-path allocation and digest failures fail closed. Logs must not contain
  seeds, keys or digests.

## 8. Decision record

This proposal chooses explicit per-forward policies, required keys/seeds,
weighted HRW, deterministic integer scores, static endpoint identities and reuse
of existing health/retry policies. It introduces no ring-size or virtual-node
settings, hash_on string enum, automatic Cookies, dynamic target IDs or state
store. Before extending to DNS, IPv6 or a management plane, define stable target
identities and distributed configuration consistency. Resolver-result array
indexes must never serve as target identities.


## Implementation notes

The implementation uses the existing compiled string-constant ownership for
seeds rather than introducing a separate policy table. Each forwarding operation
emits one `ReqSetHash` before request rewrites and the terminal forwarding result;
the verifier checks the constant seed, key types, distinct static endpoints and
that the terminal has exactly one hash operation in its block. This preserves
native artifact ownership after source removal without adding another loader
format. Native ABI is 23 (22 was the previous version).

`ForwardLoadBalance` holds the 32-byte digest, a validation status and the gRPC
error-mapping flag. It remains trivially constructible for the HTTP/2 slab pool.
Its size is 38 bytes; on x86-64 `Connection` grows from 6232 to 6264 bytes.
Existing H2 pending/async copies carry the complete metadata by value. Selection
uses the original pinned configuration and recalculates only endpoint scores on
retry. Normal requests do not parse HTTP again merely to hash the key.

The shipped expression subset covers literals, bound locals, scalar request
reads, optional unwrapping/fallback and string concatenation. Other expression
kinds reject until their purity is established. Transparent WebSocket upgrades
and CONNECT reject with 503; this change does not add a hash policy to the
`websocket(...)` builder or explicit connection waits.

The independent Python oracle in `tests/test_consistent_hash.py` checks live
HTTP/1 and HTTP/2 routing against the specified digest and integer algorithm,
including reordered endpoints, multiple shards, IP keys, zero weights and invalid
keys. `test_hash` checks golden vectors and 100,000-key weighted distribution and
remapping properties. Dedicated frontend, JIT and native tests cover validation,
timer suspension, digest ownership and execution after source removal. These
checks establish the Rut algorithm; they do not imply byte-for-byte Ketama
placement compatibility with Kong or completion of every deployment/performance
gate listed above. Performance experiments remain outside default CI.


### Validated scope and remaining gates

See [the validation record](consistent-hash-validation.md) for commands and counts.
The ordinary HTTP/2-to-HTTP/1 proxy retains its existing single async-slot limit;
this change does not add concurrent ordinary proxy streams to one connection.
The same-connection stream-isolation fixture closes each upstream response.
An io_uring upstream-drain 502 also reproduces with `.roundRobin` when that fixture
keeps the origin connection alive; it is not treated as a passing hash test.
Concurrent gRPC RPC affinity/accounting is covered separately. Cross-architecture
execution and production performance/cancellation stress gates remain open.
