# User Code Verification

Rut can use the runtime TLA+ model as a reference point, but TLA+/TLC should not
be the primary verification engine for user code. It is too general for Rut's
hot path: it brings a Java dependency, explores more machinery than Rut needs,
and is not shaped around fast per-route feedback.

The tractable product direction is a Rut-specific verifier:

> Compile Rut user-code IR into a small verification automaton and run a
> purpose-built checker that proves Rut protocol properties: legal state
> transitions, callback-slot hygiene, yielded handler wakeups, fail-closed
> behavior, deadlock freedom, and progress under explicit fairness assumptions.

## Source of Truth

The verifier should consume Rut's DSL/RIR, not generated C++ or JIT machine
code. The IR should be the single semantic source for:

- generated runtime/JIT code,
- generated verification automata,
- a manifest that maps IR operations to runtime transitions.

This avoids reverse-engineering implementation details and gives the checker a
small, stable language to reason about.

## Why Not TLA+ as the Main Engine

TLA+ remains useful for the runtime's abstract design, but it is not the right
execution engine for checking every user route:

- It depends on TLC and Java in developer/CI environments.
- It is optimized for general state-space exploration, not Rut's restricted
  event-machine shape.
- The generated specs would still require a translator, so the trusted boundary
  does not disappear.
- Liveness and fairness configuration is easy to make too weak, too strong, or
  too slow.
- The feedback loop should be close to parser/type-checker speed for common
  routes.

Rut should instead keep the TLA+ model as an oracle for validating the checker
design and a source of test vectors for the custom engine.

## Verification Automaton

The first useful handler model can be a finite automaton:

- handler state/basic-block id,
- terminal responses,
- `wait(ms)` and event waits,
- `wait any { ... }` race arms,
- upstream connect/send/recv waits,
- `forward` actions,
- fail-closed error responses.

The verifier should compose this handler automaton with a built-in model of the
Rut runtime protocol. This model should be small enough to live in native code
and run deterministically without external solvers.

Each automaton node should carry:

- the handler program point,
- the abstract runtime state,
- active callback slots,
- pending yield kind and target,
- pending runtime operation class,
- bounded symbolic facts needed by Rut's control-flow rules.

## Properties to Check

Safety properties:

- yielded handlers are in `ExecHandler` with no stale callback slots,
- only declared wait arms can resume a handler,
- upstream events cannot wake a handler waiting on a different upstream target,
- proxy/connect failures move to a closed or `Sending` fail-closed path,
- terminal response paths do not leave proxy or body-streaming callbacks behind,
- keepalive and pipeline recovery return to `ReadingHeader` with clean slots.

Deadlock checks:

- no modeled state is stuck without an allowed next action,
- each submitted timer/connect/send/recv has a modeled completion or failure
  path,
- runtime and handler states agree on which event can advance the system.

Liveness checks:

- under fair timer and IO-completion assumptions, each request eventually
  reaches a terminal response, proxy completion, close, or an explicitly allowed
  waiting state,
- handler event loops that repeatedly yield are distinguishable from cycles that
  never yield, return, or forward.

Fairness must be explicit. Without assumptions such as "an armed timer
eventually fires" or "a submitted send eventually succeeds or fails," any
network program can be modeled as not making progress.

## Custom Checker Shape

The checker can be much simpler than a general-purpose model checker:

- Use an explicit-state graph over Rut's finite protocol state.
- Represent callback slots and pending operations as compact bitsets/enums.
- Use worklist reachability for safety and deadlock checks.
- Use strongly connected components for livelock/progress checks.
- Run route-local checks first, then optionally compose multiple routes only
  where shared runtime resources matter.
- Emit counterexample traces in Rut terms, not TLA+ terms.

This should make checks fast enough for normal CI and eventually for local
developer feedback during compilation.

## Infinite Loops

The custom checker can find finite-state livelocks and cycles in the abstract
handler automaton. It cannot prove termination for arbitrary native code.

Rut should therefore split the problem:

- Static CFG checks reject handler cycles that contain no `yield`, `return`,
  `forward`, or provably bounded progress.
- The verifier checks the remaining event-driven cycles under fairness.
- Runtime watchdogs or fuel limits remain necessary for any native or
  insufficiently restricted user-code escape hatch.

## What This Does Not Prove

This is not a full C++ verifier. It does not prove:

- arbitrary arithmetic or string manipulation correctness,
- memory safety or absence of undefined behavior in generated native code,
- every kernel/network behavior,
- correctness of the IR-to-automaton translator by itself.

The translator risk should be reduced by generation discipline: both runtime
code and verification automata should come from the same IR, and CI should
compare the generated manifest against runtime transition APIs and checked
automaton actions.

## Prior Art

Useful reference points:

- PlusCal: an imperative-looking algorithm language that translates to TLA+ for
  TLC model checking.
- Quint: a typed, executable specification language with TLA-style semantics and
  model-checker integration.
- P: an event-driven state-machine language with systematic exploration of
  asynchronous behaviors.
- Dafny, F*, and Verus: verification-oriented languages where code and
  specifications are part of one workflow.
- Kani/CBMC-style tools: implementation-level model checking for bounded
  program properties, complementary to TLA+'s protocol-level modeling.

The closest shape for Rut is a mix of P's event-machine discipline, PlusCal or
Quint's generated model-checkable actions, and Dafny's single-source semantic
discipline. The implementation should be closer to P's specialized checker than
to invoking TLC for every route.

## Incremental Plan

1. Define a small handler-verification IR covering terminal responses, timers,
   event waits, upstream waits, and forward.
2. Generate a compact handler automaton plus an action manifest from that IR.
3. Implement a native explicit-state checker for safety and deadlock checks.
4. Add SCC-based progress checks for Rut-specific liveness properties under
   explicit fairness assumptions.
5. Cross-check the checker against small TLA+ reference cases while the engine
   is young.
6. Compare the manifest against runtime transition helper names and generated
   JIT metadata in CI.
7. Extend the IR only when the corresponding abstract semantics and checks are
   clear.

The first prototype should model one or two representative handlers, not the
whole language. A good initial target is a handler with `wait any { ... }`, a
timer timeout branch, and an upstream connect/send/recv path.

## Current Compiler Checks

RIR function verification is a mandatory gate for every handler passed to LLVM
code generation, including direct RIR clients. A handler does not need Phi nodes
or HTTP calls to trigger verification. A plain non-yielding control cycle or a
wait whose declared arms disagree with the modeled pending operations prevents
code generation for the entire module. Yielding handlers also pass a native
progress check and bounded wait-lifecycle exploration.

The first entry point is RIR graph validation. The native concurrent checker
then operates on finite actors and shared protocol facts, without Java, LLVM,
exceptions, RTTI, or an external solver.

Covered today:

- every block has exactly one final terminator,
- branch and jump targets point at existing blocks,
- all blocks are reachable by default,
- RIR yield terminators are lowered to the executable `YieldTimer` state-machine
  boundary; non-lowered yield opcodes are rejected,
- encoded yield kind, next-state, and payload fields match function yield
  metadata for every block, including dead blocks when reachability is relaxed,
- each yield state has exactly one producer: duplicate and missing encoded
  `next_state` values are rejected,
- yield functions declare a supported resume mapping, and verifier reachability
  starts from the same state-zero dispatch root used by codegen,
- lowered yield kinds are restricted to runtime-schedulable wait/event kinds,
- a small runtime-protocol model classifies each lowered yield by pending
  operation, callback slot, and submit/completion/fail-closed transition shape,
  and rejects yield shapes that the event loop cannot safely schedule, such as
  upstream connect/recv/send yields without a target payload,
- runtime-protocol verifier failures include a compact Rut-facing trace with
  the yield kind, payload, modeled pending operation, callback slot, and failure
  reason,
- a handler-verification automaton MVP summarizes route terminators, yields,
  resume edges, and runtime transition counts for the next explicit-state
  checker,
- a first route-local automaton check rejects synchronous CFG cycles made only
  of branch/jump nodes, before Rut attempts larger runtime composition.
- a local runtime checker compares yield nodes with declared
  wait-arm masks, callback slots, pending operations, completion transitions,
  and fail-closed transitions,
- the current `wait any { downstream.recv(), timer(ms) }` subset carries an
  exact verifier-visible arm mask even though the runtime ABI still uses
  `YieldKind::Any`.

The concurrent layer adds:

- exact-state BFS over all enabled action interleavings, with collision-safe
  state deduplication rather than approximate bit-state hashing,
- reachable nonterminal states without enabled actions reported as deadlocks,
- action assertions and state invariants for ownership and callback safety,
- terminal-resource checks, so terminating with outstanding modeled IO is an
  error rather than an accepted end state,
- iterative SCC analysis for infinite nonterminal executions under explicitly
  selected weak-fairness groups,
- handler progress checks that include yield/resume edges; an optional return
  or failure exit does not excuse a cycle that can keep completing waits,
- owned counterexample prefixes and fair cycle witnesses, with explicit trace
  truncation and action/actor identities,
- compile failures on exhausted state/edge limits or allocation failure.

The state-space model supports up to eight finite actors and 64 shared Boolean
facts. The default search limits are 32,768 states, 262,144 edges and 4,194,304
action/invariant checks (including disabled actions). The
scheduler is assumed to take an enabled action eventually; additional fairness
groups prevent a particular completion class from being starved by other work.
Weak fairness does not force an intermittently enabled action, an error outcome,
or one particular route branch to be chosen.

## Known Peer Contracts

`verify::check(Model)` checks a complete finite protocol composition. For actual
RIR handlers, `rir::VerifyOptions::environment` accepts a
`rir::VerifyPeerEnvironment`: a finite peer model and bindings to concrete yield
blocks in one function. The compiler generates the handler actor from its RIR;
it does not rely on a manually copied handler specification.

Each `VerifyPeerBinding` identifies the yield block, shared facts published on
submission, completion prerequisites, and facts consumed on completion. Peer
actions run independently. Thus a receive before a send can deadlock when the
peer only replies after observing that send, while the send-before-receive
version completes. The peer contract can also represent timers, retries,
failure replies and ownership handoffs.

Bindings cover single event/timer arms and explicit two-arm OR waits.
`VerifyPeerBinding::arms` must name each actual wait-arm bit exactly once;
missing, duplicate, extra, and combined bits reject the contract. Completion
prerequisites and consumed facts belong to each arm separately, so a timeout
can release a receive that never completes. The resumed CFG remains a
conservative abstraction of both data-dependent branch outcomes.
Submission assertions check required ownership or acknowledgement facts before
publication. Peers must describe finite required exchanges, including their
terminal states and resource invariants.

A supplied environment requires every yield in its selected function to be
bound by default. Partial contracts require explicitly setting
`require_all_yields_bound = false`; omitted yields then retain the eventual
external-completion assumption. A partial contract is not a whole-handler
protocol proof. Other functions keep their own source-only verification scope.

The contract can be supplied to `rir::verify_function`, `rir::verify_module`,
or `jit::codegen` through verification options. Source-only compilation has no
peer contracts: upstream addresses do not reveal server behavior. Its progress
result assumes submitted external operations eventually complete or fail and
does **not** establish absence of mutual waits with unknown network services.
There is currently no `.rut` peer-contract syntax or CLI contract loader.

## Wait Lifecycle and Race Coverage

`verify::build_wait_protocol_model` generates a contract for two consecutive
waits, each with one or two event arms. Independent completion actors explore
both winners, close and partial-submit failure, late loser/cancel-target
completion, resubmission, and final reclamation. Cancellation acknowledgements
and target completions are independent resource owners: either may arrive
first, and reclamation requires both to drain. Targets that finish before a
cancel is submitted need no acknowledgement. Per-operation fairness assumes
an outstanding operation eventually delivers a completion or cancellation
target completion, and every submitted cancellation eventually acknowledges.

All ordered pairs of wait shapes used by a function are checked, including
different event kinds and one-arm/two-arm transitions. Assertions require a
single owner to resume a wait, generation-correct
completion, cleared losing callbacks, and no reclamation with outstanding
operations. Mutation tests remove each protection and require an executable
counterexample. Successful models are checked for every arm shape used by a
function, within explicit bounds.

This is a logical wait-ownership contract, not an extraction of the C++ event
loops. It models one acknowledgement per abstract submitted cancel, but not
kernel CQE flags, concrete backend cancellation counts, multishot receive
deliveries, concrete buffers, arbitrary thread data races,
or all pending-operation accounting. A persistent multishot receive can supply
a new logical wait and is not automatically a stale completion. Connecting
these runtime details to the contract still requires implementation tests and
maintained abstraction mappings; passing this model does not prove either
backend's implementation correct.

The handler CFG abstraction follows both branch outcomes without proving data
predicates. Reported cycles are possible abstract executions. There is no
annotation that silently exempts a yielding loop; finite iteration must be
lowered without a potentially infinite CFG cycle or gain a proved progress
measure before such loops are admitted.

## Validation and Counterexamples

Run the native checks with:

```bash
cmake --build build --target test_concurrency_verifier test_rir test_jit
./build/tests/test_concurrency_verifier
./build/tests/test_rir
./build/tests/test_jit
```

The `runtime-state-model` CI job also checks 29 exported finite cases against an
independent TLA+ transition semantics. TLC and the native engine must agree on
success, deadlock, livelock and safety failures, including weak-fairness cases.
This reference check uses the project's existing pinned TLC artifact:

```bash
python3 scripts/check_concurrency_model.py \
  --checker build/tests/test_concurrency_verifier --jar /path/to/tla2tools.jar
```

`jit::codegen` can return the owned `rir::VerifyResult` to its caller. The
compiler loader formats verification failures with function, block and path
details, instead of reducing them to a generic LLVM failure. Peer/protocol
actor locations are labeled separately from RIR block paths.

## Runtime Continuation Scheduling

Event waits return control to the shard loop. An empty downstream send also
suspends: the loop queues its already-ready continuation instead of recursively
invoking the handler. The intrusive queue is bounded by live connections and
needs no allocations. Epoll and kqueue keep the 64-owner FIFO drain; when the
synthetic completion ring is full, nonempty sends are retained in the existing per-owner
send state and completed from writable readiness. io_uring keeps the same
64-owner drain and does not use this synthetic ring. New waits defer to a later
turn, and pending ready work makes kernel polling nonblocking. Close/free
removes queued owners. Generation and continuation-state checks protect
detached batches against close/reuse.

`spec/wait_scheduler.tla` additionally models publication, FIFO batch extraction,
callback execution, kernel polling, IO completion, peer close, slot reuse and
shutdown as distinct actions. TLC checks safety and eventual completion or
cancellation of each generation-qualified wait obligation. The checked bounds
are one/two owners, two waits per generation, two generations, and batch limits
one/two. Separate C++ tests exercise the actual 64/65/129-owner boundary and
continuous re-waits, as well as closing/reusing another owner in a detached
batch and ignoring an old Send event while a ready continuation owns the wakeup.
The TLA model does not represent backend completion-ring capacity or syscall
submission; those properties are covered by C++ scheduler/backend tests, not
claimed as TLC-proven.

Progress assumes a weakly fair scheduler and handler publication. IO delivery
is strongly fair across poll opportunities: a pending completion eligible at
repeated polls eventually arrives. Weak fairness of that poll-only delivery is
insufficient, since eligibility is intermittent. Explicit negative cases remove
each fairness assumption and must produce a liveness counterexample. No claim
is made that an unresponsive external service must produce a successful reply.

CI checks three healthy TLC configurations and ten defective variants. The
variants cover inline resume, LIFO ordering, same-turn re-draining, missing
generation fencing, missing close/shutdown cancellation, stale event takeover,
blocking polling with ready work, and absent scheduler/IO fairness. A syntax,
tool or timeout failure is not accepted as a counterexample. Concrete C++
mutation checks separately remove the generation fence, reverse FIFO order and
change the batch limit; the actual regression tests must reject every compiled
variant through test assertions. Temporary header overlays leave production
sources, build objects and the baseline executable unchanged.

Run the focused checks with:

```bash
cmake --build build --target test_wait_scheduler
./build/tests/test_wait_scheduler
python3 scripts/check_wait_scheduler_model.py --jar /path/to/tla2tools.jar
python3 scripts/check_wait_scheduler_mutations.py --build-dir build
```

The model uses the existing pinned TLC artifact. Ordinary CTest runs the C++
tests and a source-manifest drift check without requiring Java. The required
`Runtime state model` CI job runs TLC explicitly, and Clang Debug CI checks the
C++ mutations. Both retain counterexample logs as CI artifacts.

The manifest links model actions to runtime/test symbols and checks the batch
constant; it is a structural drift check. This bounded model plus implementation
and mutation tests is **not a proof of refinement of C++ to TLA+**, nor a proof
of arbitrary kernel CQE/buffer/accounting behavior. The lifecycle and peer-model
bounds described above still apply. kqueue execution still requires macOS.

## io_uring Upstream Retirement

`spec/upstream_retirement.tla` expands coverage below the logical wait layer.
It starts after transfer into the exact-episode retirement ledger, with each
cancel either submitted or deferred because the SQ is full. One operation
represents Recv; two represent concurrently owned Send and Recv. Bounds are
one/two operations and one/two episodes, with one independently completing
non-retirement operation sharing `pending_ops`.

Separate actions represent target final CQEs, cancel final CQEs, multishot
`MORE` (including cancel records), failed/retried cancel submission, duplicate,
wrong-auxiliary and stale-episode records, downstream close, slot reclamation
and reuse. Safety requires exact aggregate accounting, retry bits owned only
by outstanding targets, disjoint cancel/retry ownership, no callbacks for old
records, no release on `MORE`, and exactly one reclamation per episode after
all owners drain. Progress assumes that each outstanding target and submitted
cancel eventually delivers a final CQE, together with fair close, unrelated
completion, reclamation and reuse. It does not assume SQ retries always succeed:
a target can finish before the next cancellation attempt.

The required runtime-state CI job checks four healthy configurations, ten
safety mutations and two missing-fairness liveness counterexamples. Initial
safety violations must include an actual initial-state dump; transition
violations and liveness failures must include a trace. Parse errors, missing
trace evidence, wrong exit status, process failure and timeouts fail the gate.
Model, config and TLC log artifacts are retained when requested.

```bash
python3 scripts/check_upstream_retirement_model.py --jar /path/to/tla2tools.jar \
  --output-dir /tmp/upstream-retirement-tlc
./build/tests/test_network --filter=iouring_retirement,iouring_episode
python3 scripts/check_upstream_retirement_mutations.py --build-dir build \
  --output-dir /tmp/upstream-retirement-mutations
```

The concrete regression dispatches all 24 permutations of Send/Recv target and
cancel finals through the production loop, injecting `MORE`, duplicate, wrong
auxiliary and stale records between finals and reusing the allocator slot.
Existing tests cover SQ-full retry, final-before-retry, provided-buffer return,
second-episode close and exactly-once reclamation. Two temporary C++ header
mutations remove the `MORE` and exact-ownership checks; the permutation test
must reject each with assertions. Skipped io_uring initialization is not a
passing mutation baseline. Clang Debug CI runs these checks and preserves
implementation counterexamples.

The manifest is a structural drift map to implementation/test symbols, not a
refinement proof. This is an independently maintained finite model, not code
extraction. It does not model concrete provided-buffer IDs or their return
accounting, socket/syscall behavior, memory ordering, maximum episode overflow
quarantine, TLS buffers, or the full downstream close ledger. Provided-buffer
handling and maximum-episode behavior remain implementation-test coverage.
Epoll's synchronous retirement is outside this io_uring-specific model. These
checks add no language feature and make no claim about all runtime protocols.

## Synchronization Design Scenarios

`spec/synchronization.tla` separately describes two nonblocking submissions,
AND/OR result collection, owner application before acknowledgement, explicit
queue-full failure, and timeout exits. Its ten configurations include required
counterexamples for collection before readiness, acknowledgement before apply,
a parked owner waiting on itself, and waiting before submission. The CI job
requires each negative configuration to fail with its expected property class.
The native/TLC reference cases additionally cover cyclic owner waits, duplicate
submission, early all-resume, and cancellation-acknowledgement retirement.

```bash
python3 scripts/check_synchronization_model.py --jar /path/to/tla2tools.jar
```

`submit`, handle-based `wait`/`all`/`any`, `notify`, and `consistent: true` remain
unimplemented source-language design forms. Their models check bounded design
contracts, not shipped implementations. Supported `wait` and recv/timer
`wait any` handlers use the native compiler gate; RIR and codegen tests verify
that a supplied blocking contract prevents LLVM emission and a timer escape
allows it. Unknown services and the concrete runtime backends still need
separate contracts and implementation tests. None of these checks establishes
general freedom from distributed deadlock.

## Compiler-Generated Protocol Cross-Checks

`build_handler_protocol_model` now owns the shared composition path used by the
compiler gate and offline exporters. It builds handler actions from the actual
RIR automaton, adds the supplied peer actions and per-arm completion guards,
and retains the peer invariants and terminal-resource checks. It does not run
a search by itself. Its owned action arena is reset on rebuilding; failure
leaves no exportable partial model. Peer invariant storage remains borrowed.

`test_handler_reference` loads actual `.rut` fixtures through HIR/MIR/RIR,
checks the compiler verdict, and exports that same generated composition in the
existing `concurrency_reference.tla` instance format. TLC independently executes
its transition semantics. Eight cases have fixed expected verdicts: receive
before send, the corrected order, timer escape from an OR wait, blocked OR arms,
missing ownership, leaked terminal resources, a finite sleep, and a yielding
cycle. The last case deliberately mutates the lowered RIR continuation; it is
not source syntax admitting unbounded loops. The OR fixtures supply finite
explicit peer/timer contracts; no network behavior is inferred.

```bash
cmake --build build --target test_handler_reference
./build/tests/test_handler_reference
python3 scripts/check_handler_models.py --checker build/tests/test_handler_reference \
  --jar /path/to/tla2tools.jar --output-dir /tmp/handler-reference-tlc
```

Each output subdirectory retains the exported `.tla` instance, reference
semantics, TLC configuration, export diagnostics and TLC counterexample log.
The shared primitive-case runner supports the same `--output-dir` option.
Clang Debug CI checks the generated models and uploads their artifacts; the
runtime-state job also retains the primitive-case artifacts. Ordinary CTest
runs the source/composition regression and fail-closed orchestration tests
without Java. A golden verdict must agree with both the native result and TLC:
checker agreement alone is insufficient. Export failure, missing verdicts,
search exhaustion, parser errors, contradictory exit status and timeout fail
the check; a TLC timeout preserves any partial output for diagnosis.

This closes the hand-copied-handler gap for these finite fixtures, not the
concrete runtime/backend refinement gap. Branch predicates remain abstract,
peer contracts remain explicit, and the exported model's bounds and scheduler
assumptions still apply. The standalone design examples below remain useful
independent models; they are not the compiler-generated exports.

## Executable Receive-Before-Send Example

[`receive-before-send.rut`](../tests/fixtures/deadlock/receive-before-send.rut)
connects, waits for an upstream reply, and only then sends the request body.
The explicit peer contract replies only after receiving that request. With no
timeout or close escape in the contract, both sides wait forever.
[`send-before-receive.rut`](../tests/fixtures/deadlock/send-before-receive.rut)
reverses the send/receive order and completes under the same contract.

The JIT test loads both actual source files, lowers them through HIR/MIR/RIR,
binds the peer contract to their actual yield blocks, and checks LLVM admission:

```bash
./build/tests/test_jit --filter=source_receive_before_send_deadlocks_under_reply_after_request_contract
```

The bad source returns `HandlerDeadlock` before LLVM emission; the corrected
source is accepted. Without a peer contract both source files pass the local
verifier: this example does not imply that ordinary source-only compilation
can infer a remote server's behavior.

[`receive_before_send.tla`](../spec/receive_before_send.tla) is an independently
written reference abstraction, not an automatic translation of these files.
The synchronization CI script checks both configurations: the bad order must
produce `Deadlock reached`, and the corrected order must satisfy safety and
termination. To view TLC's counterexample directly (the first command is
expected to return a nonzero exit status):

```bash
cd spec
java -cp /path/to/tla2tools.jar tlc2.TLC -config receive_before_send.cfg receive_before_send
java -cp /path/to/tla2tools.jar tlc2.TLC -config send_before_receive.cfg receive_before_send
```

The bad model reaches two states: `Connect / WaitRequest`, then
`Recv / WaitRequest`, with neither request nor reply published. The corrected
model explores eight reachable states with no error. Concrete runtime timeout,
transport failure and disconnect behavior are outside this deadlock contract.

## TLA+ Role

TLA+ should stay in the project for design-level runtime invariants and for
validating the custom checker's semantics. It should not be required to verify
normal Rut user code.
