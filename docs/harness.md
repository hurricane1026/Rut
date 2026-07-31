# Rut Project Harness

Status: accepted architecture with Phase 1 implemented. The common contract,
production source target, deterministic handler executor, and simulation
parity path exist; later execution environments and drivers remain staged
below. A user-facing scenario syntax stays intentionally deferred until those
boundaries have proven stable.

## Definition

The Rut project harness is the reusable execution boundary around the compiler,
JIT, runtime, network backends, and a compiled Rut program.

It answers one question:

> Given a target, an execution environment, a workload, and an oracle, how do we
> run Rut through the intended production layer and collect a reproducible
> result?

Testing is one consumer. Simulation, capture replay, differential backend
checks, fault injection, benchmarking, fuzzing, verifier checks, debugging, and
production smoke runs are other consumers of the same boundary.

The harness is therefore not:

- another unit-test assertion framework;
- a replacement for CMake, CTest, or `dev.sh`;
- a second Rut interpreter;
- a production control plane; or
- one large executable containing every testing dependency.

Its primary deliverable is a library with explicit interfaces and lifetimes.
CLI tools and test binaries are thin drivers over that library.

## Why Rut needs it

The project currently has several partial harnesses:

- frontend tests assemble lex/parse/analyze/lower stages directly;
- JIT tests construct RIR and call native handlers;
- integration tests build event loops and synthetic connections;
- traffic replay drives captured requests through a small runtime path;
- `rut-simulate` has its own manifest, JIT setup, route matcher, and yield
  driver;
- fault-injection tests install process or thread-local syscall hooks; and
- benchmarks construct another set of runtime objects and inputs.

Each is useful, but their composition and observation boundaries differ. This
creates four risks:

1. a feature works in one driver but is unsupported or approximated in another;
2. lifecycle and cleanup bugs are fixed repeatedly in separate fixtures;
3. simulation accidentally diverges from the production handler ABI; and
4. CI results cannot be compared because each tool reports a different unit of
   work and failure model.

The project harness unifies composition without forcing all modes to use the
same fidelity level.

## Core model

Every run is described by six independent parts:

```text
HarnessRun = Target
           + ExecutionLayer
           + Environment
           + Driver
           + Oracle
           + ArtifactPolicy
```

### Target

The target is what Rut executes or validates:

- `SourceTarget`: one root `.rut` source plus imports;
- `RirTarget`: an already constructed RIR module for compiler/JIT isolation;
- `RuntimeConfigTarget`: a prepared `RouteConfig` and handler ownership bundle;
- `BinaryTarget`: a built `rut` executable for process/loopback smoke runs; or
- `CorpusTarget`: bytes consumed by a parser or protocol fuzzer.

A target owns, or explicitly borrows, every transitive lifetime. For a source
target this includes source mappings, frontend arenas, RIR storage, JIT code,
and `RouteConfig`. The existing `LoadedProgram` contract should become the
source-target implementation rather than be duplicated.

### Execution layer

The layer states which production boundary is being exercised:

| Layer | Boundary | Typical use |
|---|---|---|
| `Compile` | lexer through verifier/lowering | diagnostics, language corpus |
| `Handler` | compiled handler ABI | fast semantic cases, wait lowering |
| `Connection` | `Connection` plus callbacks and route selection | state invariants, proxy/streaming |
| `EventLoop` | epoll/io_uring backend contract | completion ordering, cancellation |
| `Loopback` | real sockets against an in-process server | HTTP/TLS/protocol E2E |
| `Process` | packaged `rut` binary | startup, signals, reload, distribution smoke |

A driver must declare its minimum layer. The harness may run it at a higher
layer, but never silently substitute a lower-fidelity approximation. Unsupported
combinations produce `Unsupported`, not a passing result.

This distinction is central: a handler-level simulation can validate a terminal
action, but it cannot claim that HTTP/2 framing or io_uring cancellation was
tested.

### Environment

The environment owns all effects outside the selected target:

- monotonic and wall clocks;
- client input/output;
- upstream connect/read/write behavior;
- backend completions and queue pressure;
- DNS, environment values, files, and entropy when exposed to Rut;
- shard count and shard selection;
- Cache and future state services;
- TLS peer and certificate metadata; and
- fault injection.

Control-plane mutation is also an environment capability. Its deterministic
port owns reload admission/outcomes, config-generation acknowledgements, and
manual upstream-health overrides. The exact authority, failure, ordering, and
replay rules are specified in `docs/control-plane-mutations.md`; a reload
activation requires the `Process` layer rather than a handler-level
approximation.

Environment capabilities are ports, not global mode flags. A run receives an
explicit `ClockPort`, `IoPort`, `UpstreamPort`, `StatePort`, and `FaultPort` as
well as a `ControlPlaneMutationPort` when required by its layer. Production
adapters call the OS. Deterministic adapters use a virtual event queue. Loopback
adapters use real local resources.

An environment advertises capabilities such as:

```text
VirtualTime | RealTime
SyntheticIO | Epoll | IoUring
Http1 | Http2 | WebSocket | Tls
SingleShard | MultiShard
ScriptedUpstream | LoopbackUpstream | ExternalUpstream
FaultsNone | FaultsScripted | SyscallInterpose
ControlPlaneSnapshot
ControlPlaneMutation
```

The runner validates required capabilities before starting. No driver should
discover halfway through a run that its environment cannot model an operation.

`ControlPlaneMutation` scenarios provide an explicit
`ScenarioSpec::control_plane_mutation` fixture. The production event loops and
the scenario driver inject the same allocation-free port into `HandlerCtx`, and
the pointer and invocation generation remain stable across resumes. Missing or
undeclared fixtures are invalid runs. Handler-layer coverage may execute the
same shard-pinned `upstream.mark` lowering and manual-health atomics as
production. Its pointer-free `UpstreamServersView` pins the observed config
generation, and selection scenarios apply the same manual-over-local health
priority as production. HTTP/1 requests, suspended HTTP/2 streams, and
terminate-mode WebSocket sessions increment the same per-program lifetime
counters as production, including abnormal-close release, while each shard
acknowledges only the generation it installed at a command boundary. Activation
still requires the `Process` layer.

`stats()`/`metrics()` scenarios use the `ControlPlaneSnapshot` capability and
must supply `ScenarioSpec::control_plane_snapshot`. The fixture is a bounded,
pointer-free value copied into `HandlerCtx` before the first invocation. It is
not refreshed on resume, so a replay observes exactly the same bytes even when
the handler yields. Omitting either the declaration or fixture is an invalid
scenario rather than an implicit all-zero snapshot.

### Driver

A driver supplies work and decides when a run is complete. Core drivers are:

- `CompileDriver`: compile/check a source or diagnostic corpus;
- `ScenarioDriver`: declarative request/event cases;
- `ReplayDriver`: feed captured production traffic;
- `DifferentialDriver`: run identical work through two targets/environments;
- `BenchmarkDriver`: warm up, sample, and aggregate a fixed workload;
- `FuzzDriver`: turn input bytes into bounded operations;
- `FaultDriver`: enumerate or script failure points;
- `VerifierDriver`: check route automata and runtime invariants;
- `SoakDriver`: run a bounded-duration workload and monitor invariants; and
- `DebugDriver`: execute one case with full semantic trace and optional pause
  points.

Drivers share lifecycle and observation contracts but retain their own workload
models. A benchmark should not be encoded as thousands of test cases, and a
fuzzer should not parse a test DSL on every input.

### Oracle

The oracle evaluates observations. It is separate from the driver so the same
workload can support different questions:

- exact response/status/header/body expectations;
- recorded-vs-current replay comparison;
- epoll-vs-io_uring differential comparison;
- interpreter/reference-vs-JIT comparison if a reference executor exists;
- runtime state/callback-slot invariants;
- no-crash and resource-bound fuzz properties;
- latency/throughput/allocation benchmark budgets; or
- verifier safety and progress obligations.

Oracles consume stable observations, never raw internal addresses. Multiple
oracles may observe one run, for example response equality plus connection-state
invariants.

### Artifact policy

Artifact collection is independent of pass/fail logic:

- semantic trace;
- diagnostics and source spans;
- request/response bytes;
- RIR or LLVM IR on compiler failure;
- connection debug snapshots;
- capture/replay files;
- benchmark samples;
- coverage/profiles; and
- crash or sanitizer metadata.

The policy controls `Never`, `OnFailure`, or `Always` per artifact class and
enforces byte limits. CI and local debugging can therefore run the same driver
without changing semantics.

## Harness lifecycle

Every adapter follows one state machine:

```text
Created
   -> Prepared       target validated and environment capabilities matched
   -> Started        owned runtime/JIT/backend resources are live
   -> Driving        workload and completions may advance
   -> Quiescing      no new work; pending operations drain or cancel
   -> Observed       final snapshots and artifacts captured
   -> Destroyed      every owned resource released
```

Failure from any state transitions through `Quiescing` and `Destroyed`. Cleanup
is never delegated to a test assertion or process exit.

The harness result records both the primary result and cleanup result. A correct
HTTP response followed by stale callbacks, leaked state, or a failed backend
shutdown is not a pass.

Recommended API shape:

```cpp
struct HarnessSpec {
    TargetSpec target;
    ExecutionLayer layer;
    EnvironmentSpec environment;
    DriverSpec driver;
    OracleSet oracles;
    ArtifactPolicy artifacts;
    RunLimits limits;
};

HarnessResult run_harness(const HarnessSpec& spec, ArtifactSink& sink);
```

The public specification contains bounded values and stable identifiers. Large
mode-specific state lives in owned implementation contexts, not in one giant
tagged struct placed on the stack.

## Shared execution engine

The harness should not create a universal fake runtime. It should provide a
shared driver around existing production components:

```text
                    Source / RIR / Config
                             |
                     Target preparation
                             |
        +---------------- HarnessRunner ----------------+
        |                       |                        |
 EnvironmentAdapter       ExecutionAdapter       ObservationBus
        |                       |                        |
 virtual / OS         handler / conn / loop       stable events
        |                       |                        |
        +-------------- production code ----------------+
```

Execution adapters are intentionally layered:

- `CompileExecution` calls frontend/verifier/lowering stages;
- `HandlerExecution` owns the JIT handler context and resume state;
- `ConnectionExecution` owns `Connection`, route selection, callbacks, arenas,
  and response serialization;
- `EventLoopExecution<Backend>` owns a real event loop and its resources;
- `ProcessExecution` owns child process, ports, signals, and output capture.

Higher layers may build on lower-layer ownership helpers, but a lower layer does
not simulate claims belonging to a higher one.

The state-machine driving code in `rut-simulate` should be extracted into
`HandlerExecution`. Simulation then becomes one driver/environment combination
instead of a separate executor. Traffic replay should likewise use a replay
driver over `ConnectionExecution` where possible.

## Observation bus

Production components emit bounded semantic observations through an optional
sink. The sink must be cheap or compiled out when unused.

Initial event families:

- compile stage entered/failed and diagnostic;
- route selected;
- handler entered/yielded/resumed/terminated;
- wait armed/completed/cancelled;
- upstream selected/connect/request/response/failure;
- response status/header/body/close action;
- connection state and callback-slot transition;
- backend operation submit/complete/cancel;
- Cache lookup/write/eviction using hashed or redacted keys; and
- invariant violation and resource-limit hit.

Events use stable operation names, logical IDs, bounded payloads, and virtual or
real monotonic timestamps. They exclude pointers, callback addresses, allocator
offsets, LLVM block names, and nondeterministic file descriptors.

This bus is the common source for assertions, differential comparison, debug
traces, replay diagnostics, and benchmark counters. It is not a general logging
framework and must not change dispatch behavior.

Traffic replay and typed source scenarios publish response status and response
body as separate semantic observations before the connection buffer can be
reused. The body label is valid for the synchronous observation callback, which
must copy any bytes it wants to retain. The event carries the full wire-body
length, up to 4096 exact bytes, and an explicit truncation flag.

## Deterministic environment

Determinism is an adapter, not a property imposed on every mode. The
deterministic environment provides:

- virtual monotonic and wall time;
- an ordered completion queue;
- scripted upstream behavior;
- synthetic client reads/writes and chunk boundaries;
- explicit queue pressure and failures;
- fixed shard routing; and
- resettable bounded state.

It advances only when the driver requests progress. If a handler yields with no
declared completion or timer, the result is `Stalled`. Same-time events require
an explicit order. Every run has event, resume, byte, and virtual-duration
budgets.

This environment supports fast scenario tests, replay diagnostics, fault
enumeration, and deterministic debugging. It does not replace real epoll,
io_uring, TLS, HTTP/2, or kernel lifecycle coverage; those use higher execution
layers and different environment capabilities.

## State isolation

Isolation is a harness policy shared by all drivers:

- `Run`: fresh state for every workload item;
- `Group`: named items share state, connections remain isolated;
- `Process`: the whole driver shares one program/runtime instance; and
- `External`: state belongs to a separately managed target and cannot be reset
  by the harness.

The default for scenarios and fuzz cases is `Run`. Replay normally uses
`Process` to preserve captured ordering. Benchmarks use `Process` with an
explicit warmup boundary.

Shard identity is always part of a stateful workload item. The harness must not
make per-shard Cache look exact or globally shared. Internal Cache contents are
debug observations, not a source-of-truth assertion API.

## Driver applications

### Project tests

C++ tests use a typed `HarnessSpec` builder and the existing test framework for
assertion presentation. User-program black-box tests may later receive a narrow
`.ruttest` scenario frontend that compiles to `ScenarioDriverSpec`. That syntax
is a consumer of the harness, not the harness architecture itself.

### Simulation

`rut-simulate` becomes:

```text
Source/RIR target + Handler layer + Deterministic environment
+ Replay driver + recorded-result oracle
```

Unsupported effects remain explicit. Its current manifest can be supported by
an input adapter during migration.

### Traffic replay

Replay becomes:

```text
RuntimeConfig target + Connection/EventLoop layer
+ capture-backed environment + Replay driver + differential oracle
```

The result distinguishes mismatch, malformed capture, unsupported effect,
runtime failure, and cleanup failure instead of collapsing them into skipped or
failed counters.

### Backend differential checks

The same normalized workload runs once with epoll and once with io_uring.
The oracle compares semantic events and terminal bytes while allowing declared
backend-only events to differ. This catches backend drift without comparing
incidental completion batching or file descriptors.

### Fault exploration

Existing RAII syscall interposition remains useful at EventLoop/Loopback layers.
At Handler/Connection layers, a scripted `FaultPort` is preferable because it
can enumerate logical failures such as the Nth upstream write or timer arm.

A fault driver records which fault points were reached, which were injected,
and whether cleanup invariants held. It can then iterate one fault point at a
time under a global case budget.

### Benchmarking

The benchmark driver separates:

- setup/JIT time;
- warmup;
- measured operations;
- cooldown/quiescence; and
- artifact/report time.

Observers used in measured sections must be declared so instrumentation cost is
visible. Benchmarks emit raw samples plus environment/build metadata; pass/fail
budgets are optional CI policy, not embedded in the workload.

### Fuzzing

Fuzz adapters decode bytes directly into bounded target inputs or event
schedules. They reuse lifecycle, limits, sanitizer artifacts, and cleanup
checks, but never require parsing a scenario manifest. A reproducer serializes
the decoded semantic workload as well as retaining the original bytes.

### Verification

The verifier driver operates at `Compile` layer over the same HIR/MIR/RIR route
automata. Counterexamples are converted into semantic event schedules that can
be handed to a compatible scenario/debug driver. This connects proof failures
to an executable reproduction instead of creating a separate reporting world.

## Result model

All drivers return a common envelope:

```text
HarnessResult
  identity: run/target/driver/build IDs
  outcome: Passed | Mismatched | Failed | Unsupported | Stalled | Invalid
  phase: prepare | start | drive | quiesce | observe | destroy
  primary diagnostic
  cleanup outcome
  counters and timings
  capability set
  artifact references
```

Driver-specific results are attached as bounded payloads. Common outcome names
must retain the same meaning across CLI tools and CI.

Suggested process exit contract:

- `0`: all selected runs passed;
- `1`: mismatch, runtime failure, invariant failure, stall, or unsupported run;
- `2`: invalid CLI, target, manifest, or capability combination; and
- `3`: harness internal or cleanup failure.

`Unsupported` fails by default. A caller may explicitly count it separately,
but it cannot be reported as passed.

## Repository structure

Proposed ownership:

```text
include/rut/harness/       stable specs, results, ports, observation schema
src/harness/               runner, lifecycle, execution/environment adapters
tools/harness/             rut-harness CLI and manifest/input adapters
testing/harness/           test builders, matchers, fault enumeration helpers
tests/harness/             harness self-tests and adapter contract tests
```

Production `rut` does not link `rut_harness`. Runtime observation hooks live in
small production-owned headers and are disabled or null-sinked in normal builds.
The harness may link compiler, JIT, and runtime libraries; the dependency must
never point in the opposite direction.

CMake targets:

```text
rut_harness_core       lifecycle, specs, results, observation bus
rut_harness_compile    compiler target/execution adapter
rut_harness_runtime    handler/connection/event-loop adapters
rut-harness            project CLI
```

Splitting targets keeps compiler-only fuzzers free of runtime/JIT dependencies
and lets sanitizer builds use the non-JIT subset.

## CLI role

The project CLI is an adapter and orchestrator, not the core API:

```text
rut-harness compile ...
rut-harness scenario ...
rut-harness replay ...
rut-harness diff --left epoll --right io_uring ...
rut-harness faults ...
rut-harness bench ...
rut-harness debug ...
```

`dev.sh` may expose convenient wrappers such as `./dev.sh harness scenario`,
while CTest continues to own test discovery and scheduling. The harness emits
human output and one versioned JSON result schema; JUnit and benchmark formats
are reporters derived from that result.

The core should not commit to a universal manifest first. Typed C++ specs should
stabilize the lifecycle and capability model. Each CLI driver can then accept
the smallest appropriate input: capture files for replay, corpus bytes for
fuzzing, benchmark definitions for bench, and a future `.ruttest` file for
program scenarios.

## Limits and safety

`RunLimits` is mandatory and includes:

- source, manifest, capture, request, response, and artifact bytes;
- routes, connections, upstreams, headers, shards, and retained state;
- handler resumes, backend completions, fault points, and semantic events;
- virtual duration and real deadline; and
- quiesce/cancel work after the driver finishes.

Limits are reported by stable names. Hitting one is a structured failure, not a
timeout, truncated pass, or process abort. Host-level watchdogs remain a final
backstop for harness bugs.

No external network, filesystem mutation, environment inheritance, or real
clock access is enabled implicitly. Higher-fidelity adapters request those
capabilities explicitly and record them in the result.

## Migration plan

### Phase 1: lifecycle and observations

Status: first slice implemented. Common contracts, source ownership, handler
execution, observations, and cleanup paths exist; the connection adapter and
its invariant checks remain part of the next runtime-focused slice.

- Define `HarnessSpec`, `HarnessResult`, capabilities, limits, and artifact
  sink.
- Wrap `LoadedProgram` as `SourceTarget`.
- Add handler and connection execution adapters without changing semantics.
- Centralize cleanup and connection state/callback-slot invariant checks.

### Phase 2: simulation and replay convergence

Status: implemented. The original manifest and capture APIs remain as
compatibility adapters.

- Extract the JIT yield/resume driver from `rut-simulate`.
- Move simulation onto `HandlerExecution` plus deterministic environment.
- Adapt traffic replay to the common result and observation model.
- Keep compatibility adapters for current manifests and capture files.

### Phase 3: deterministic environment

Status: core slice implemented. Virtual time, ordered and target-aware
completions, scripted upstream operations, resettable scripted run state,
owned scripted receive data with input/completion budgets, Nth-occurrence
logical faults, connection cleanup invariants, and typed C++ scenarios over
production-loaded Rut programs exist. Cache/rate-limit state ports now
implement `Run`, sequential `Group`, `Process`, and `External` boundaries
without turning per-shard Cache into global state. Payload content is not part
of the handler resume ABI, so full production proxy/streaming scenario coverage
remains at the EventLoop layer.

- Add virtual clock, ordered completions, scripted upstream, state reset, and
  logical fault points.
- Add typed scenario builders for C++ integration tests.
- Use them for wait, Response mutation, Cache/rate-limit, proxy failure, and
  streaming state-machine coverage.

### Phase 4: project drivers

- Add backend differential, fault enumeration, benchmark, fuzz, verifier, and
  debug drivers incrementally.
- Migrate existing fixtures only where the common harness improves fidelity or
  removes duplicated lifecycle code; do not rewrite stable unit tests merely
  for uniformity.

### Phase 5: user-program scenario frontend

- Design `.ruttest` after the typed scenario model has proven sufficient.
- Keep it declarative and compile it to the same `ScenarioDriverSpec` used by
  C++ tests.
- Expose it through `rut test` only if it is suitable as a supported user
  feature; otherwise keep it under `rut-harness scenario`.

## First implementation slice

The first PR should not attempt every driver. It should establish the seam:

1. common result, phase, capability, observation, and limit types;
2. a `SourceTarget` owner around the production loader;
3. `HandlerExecution` extracted from simulation;
4. deterministic timer completion and terminal action collection;
5. lifecycle/cleanup tests for success, compile failure, JIT failure, stall,
   limit exhaustion, and early oracle failure; and
6. migration of a small set of `test_simulate_engine` cases as parity proof.

Success means old and new simulation results agree for supported cases, while
the new runner exposes explicit phase, capability, cleanup, and semantic trace
information. It does not yet require a new test DSL.

## Acceptance criteria

The project harness is successful when:

- each supported execution layer uses the corresponding production code path;
- simulation, replay, tests, and debug runs share target ownership, lifecycle,
  limits, observations, and cleanup contracts;
- a driver cannot run with undeclared or missing environment capabilities;
- unsupported behavior is visible and never counted as passed;
- failures can be reproduced from target identity, driver input, environment
  description, and event trace;
- Cache and shard behavior retain their real isolation/consistency semantics;
- backend-specific tests can distinguish semantic parity from kernel/backend
  behavior;
- fuzz and fault runs enforce cleanup as well as no-crash properties;
- benchmarks isolate measured work from setup and reporting; and
- adding a new driver does not require another compiler/JIT/runtime composition
  path.
