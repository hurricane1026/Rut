# nginx → RUT session handoff

Updated: 2026-09-13 (Asia/Shanghai). This is a handoff snapshot, not proof that
any pending code is accepted. Recheck local and GitHub state before acting.

## Goal and roles

Translate `nginx.conf` through a separate parser/semantic model/converter into
ordinary RUT source, then compile and run it with the existing RUT toolchain.
The RUT runtime must not directly consume nginx configuration. For a declared
supported scope, prove observable equivalence against real nginx; output golden
tests alone are insufficient. Reject unsupported semantics explicitly.

The user's preferred workflow is **Astra designs, decomposes and accepts;
Luna implements**. Use one small compatibility increment at a time, followed by
different-worker review, scheduled tests, and compatibility-state updates.
Keep CURRENT to one main task and NEXT to at most three clear tasks.

The previous session repeatedly received `agent thread limit reached` both when
spawning workers and when following up completed workers, including a Terra
spawn attempt. No model switch or successful corrective assignment followed.
In this session the initial audit succeeded: Luna `handoff_audit` completed it,
then implemented the bounded correction; a different Luna `snapshot_review` reviewed
and approved the corrected patch. Spawn and follow-up both worked in this
session. Continue the small relay; do not repeat the completed initial audit.

The user authorized primary-agent implementation and explicitly labelled
self-review as an in-session fallback, then reiterated the preferred Astra/Luna
split. Do not describe self-review or same-context model switching as independent
worker review. The primary agent cannot switch its own model with the currently
exposed tools; the user selects the primary model in the client.

## Workspace and preservation

- Assigned worktree: `/home/hurricane/private/code/Rut_issue627_two_second_oracle`.
- Branch: `nginx-explicit-off-converter`, based on accepted #642 merge `f08b85ba`.
- This session started with clean worktree and local/remote HEAD both
  `6942666557d9f9a4303d40de266b640f4920f217`.
- Current #638 source candidate: `247338de`, independently **APPROVED for the
  shared-validator/control increment**, following the accepted snapshots fix
  `d345e933`. See current status for validation logs and the explicit primary
  implementation fallback used for final control corrections. Historical
  rejected candidates/reviews remain evidence. Complete candidate #639 was independently reviewed, passed normal and
  required CI, and merged as `ed0eec96`; extraction for the next capability
  witness was validated as `d9e1733a`; the ordinary-RUT wrapper is CURRENT.
- Integration base: `agent/nginx-to-rut-converter`, not `main`.
- Parent [PR #269](https://github.com/hurricane1026/Rut/pull/269) stays draft.
- The main worktree `/home/hurricane/private/code/Rut` has unrelated user WIP in
  fixture tests/protocol/topology and a privileged-broker test. Do not edit,
  stage, discard or migrate those changes as part of this task.
- Append focused commits and push code/documentation to GitHub. Preserve
  unresolved problems and failed evidence in issues. No amend/reset/rebase or
  destructive cleanup of user data.

## Read first

1. Applicable `AGENTS.md` files, if present.
2. This document and [current status](../.nginx-converter-status.md), especially
   the current candidate-CI task and completed validator/snapshots evidence.
3. [Compatibility matrix](nginx-compatibility.md).
4. [Issue #638](https://github.com/hurricane1026/Rut/issues/638), including design,
   review and capacity-blocker comments. Detailed pending handoff is preserved
   in comment `5646579364`; Astra design is in comment `5646534982`.
5. Relevant source in `tests/test_nginx_differential.cc` and
   `tests/CMakeLists.txt`. Verify control flow rather than trusting old line numbers.

Historical evidence remains in
[the status archive](archive/nginx-converter-status-2026-09.md); do not rewrite
that archive or repeat the entire repository reconnaissance.

## Accepted baseline

[PR #637](https://github.com/hurricane1026/Rut/pull/637) merged into converter
integration as `a9ebd7b9d2a884870fc9b010f8c323a8dea406ee`. The recorded final
head was `367631ef70a2c983a965e988b278932908d3b75e`; CI run `34698186843`
passed 15 ordinary jobs and required nginx job `103565197203` passed 160/160,
zero skips. This completed only #630's exact bodyless HEAD witness.

Broad #270 remains PARTIAL and #271 remains BLOCKED_BY_RUT. None of that proves
the new explicit `proxy_buffering off` scope. Verify current issue/PR state if
making new status claims; these are recorded prior-run results, not reruns.

## CURRENT: actual converter-stdout explicit-Off differential

Transport pair `da521207` is independently APPROVED and passes its first real
same-file converter-stdout nginx/RUT run (3.03s). Clang Release `-j1` build and
four focused CTests pass 4/4, zero skips, 6.13s; logs:
`/tmp/rut-638-off-pair-transport-build.log` and
`/tmp/rut-638-off-pair-transport-tests.log`. The primary agent implemented this
wrapper under the authorized fallback after the worker twice ended without
code changes. This is transport evidence only: CURRENT is selected loaded GET
bundle authentication and mutation/comparator controls, followed by independent
complete-candidate review and CI. No support promotion yet.

The nginx-side pair context extraction `176a1e96` is independently APPROVED.
Clang Release `-j1` build and three focused CTests pass 3/3, zero skips,
3.09s (nginx off oracle 1.71s, shared self-check 0.01s, ordinary-RUT
capability 1.37s). Logs: `/tmp/rut-638-off-context-build.log` and
`/tmp/rut-638-off-context-tests.log`. Context success is published only after
all original capture/config/cleanup/join checks pass; the existing oracle mode
exercises this path. This extraction is not a converter pair. CURRENT remains
its actual same-file CLI wrapper; selected loaded GET bundle and mutation
controls follow before complete candidate acceptance.

Model/provenance/lowering `a2358195` is independently APPROVED and locally
validated: Clang Release `-j1` build, full parser 192 tests / 19991 checks
(4.46s), converter CLI 0.05s, zero CTest skips. Logs:
`/tmp/rut-638-off-model-build.log`, `/tmp/rut-638-off-model-tests.log`,
`/tmp/rut-638-off-model-fixture-build.log`,
`/tmp/rut-638-off-model-fixture-tests.log`. The first parser run failed a new
sibling fixture's unsupported redirect URL; fixing it to the existing accepted
literal reached the intended off-scope assertion and passed. Review continued
APPROVE. Initial rejected patches remain `/tmp/rut-638-off-first-unaccepted.patch`
and `/tmp/rut-638-off-second-unaccepted.patch`; primary fallback corrected
remaining declaration-order/diagnostic issues and completed controls after
Luna's implementation. Different Luna reviewed the complete final result.
Luna is now implementing only differential/CMake changes; lead schedules tests.
Bounded parser/lowering and CLI stdout are now available, but no actual off
nginx/RUT pair is yet proven and no support row is promoted.

### Accepted capability and next-stage design

Capability #642 merged into converter integration as
`f08b85ba208e8955c9fca3644eb966703651af8b`, reviewed final head `da180b1c`.
CI `34734172519` passed all 14 ordinary jobs and required nginx 163/163,
zero skips, 638.52s (ordinary capability 1.32s; off oracle 1.63s;
shared self-check 0.01s). Log `/tmp/rut-642-da180-nginx-ci.log`.
#640/#641 are closed with combined proof; #638 remains open. Parent #269
was rechecked OPEN/draft. The new branch starts at the accepted merge.
The parser/model/provenance/lowering increment is now accepted locally as
recorded above. Actual converter-stdout differential is still required.

Reviewed design is in #638 comment `5650540578`: exact root loopback
listener/upstream, no URI/hide/siblings, literal `1s`; authenticate Off semantic
value and full fresh server inventory with supplied/fresh relative spans and
coherent borrows. Reuse existing full parser consumption, not another gap
scanner. Generated GET omits response_buffering for ordinary default None.
The pair must sequentially reuse the same immutable config, ports and access
path, snapshot nginx's ledger before creating RUT's empty sink, and consume
actual standalone converter stdout. Shared #638 capture/gates remain unchanged.

### Accepted capability local evidence (before final CI)

Source `f49f0885` now passes the unchanged handwritten public O2/io_uring
capability witness (first run 1.37s, zero skips), including shared negative
controls, exact prefix/probe/EOF/natural retirement/live ledger/stability and
post-join checks. Log `/tmp/rut-641-capability-first.log`. This is local ordinary
RUT evidence only; actual off converter admission/differential still remain.
The precise timer increment is independently approved, Clang Release `-j1`
built, and passes 15 focused positive-CL tests / 920 checks (1218 filtered out).
Logs `/tmp/rut-641-candidate-build.log` and `/tmp/rut-641-focused-first.log`.
Full network regression passes (1233 tests / 143522 checks, 40.95s), log
`/tmp/rut-641-network-full.log`; nginx oracle/shared-validator pass 2/2, zero
skips, 1.70s, log `/tmp/rut-641-nginx-oracle-regression.log`. Complete candidate
`ed0eec96..f49f0885` is independently APPROVED; PR/CI is the next gate.

Implementation provenance: Luna supplied the initial timer patch and tests;
the primary agent used the user's authorized implementation fallback to fix
remaining phase/send ownership and same-batch retained-body accounting and to
add cancellation/SQ controls. Different Luna independently approved the frozen
result. Both rejected patches are retained in `/tmp/rut-641-first-review-rejected.patch`
and `/tmp/rut-641-second-review-rejected.patch`. Do not describe this as Luna-only
implementation. Complete candidate range is `ed0eec96..f49f0885`; #640/#641 stay
open until final evidence and CI. Parent #269 was rechecked OPEN/draft.

### Earlier #641 implementation and failure evidence (historical)

Completion increment `119d7088` is independently approved, Clang Release `-j1`
built, and passes eleven focused positive-CL tests / 568 checks (1218 tests
filtered out), full formatting and runtime-state model checks. Another 64
adjacent buffering/GET CL0 tests pass with 3682 checks (1165 filtered out), log
`/tmp/rut-640-completion-adjacent.log`. The first build
failed on a missing `on_request_complete` declaration; the correction adds the
matching declaration for an existing explicit template instance. Logs:
`/tmp/rut-640-completion-build.log`,
`/tmp/rut-640-completion-revised-build.log`, and
`/tmp/rut-640-completion-focused-first.log`.

The first public capability run of that changed candidate still failed in
2.17s: exact normalized 127 bytes, EOF at publication+2000.190475ms, violating
the unchanged strict `<2000ms` gate. Access diagnostic contains `60\n`, but the
joint live ledger/retirement gate was not reached and failure-time retirement
was Pending. Full source/log are in [#641](https://github.com/hurricane1026/Rut/issues/641)
and `/tmp/rut-640-completion-capability-first.log`. Do not retry unchanged or
promote support. Luna is implementing precise timer activation only after
validated incomplete positive-CL stream selection; preserve preheader/CL0 and
all same-batch progress/timeout, cancellation, generation and episode rules.
The first timer candidate remains unbuilt/unaccepted after source review:
precise timer plus post-header body progress cannot reuse the incomplete-header
HTTP parser commit. A separate authenticated body-copy commit, strict semantic
phase/send proof, non-due rearm and deterministic new controls are under correction.
Rejected diff `/tmp/rut-641-first-review-rejected.patch` is based on `51907777`.
Independent review, unchanged public proof and full CI remain required.
#640 remains open pending combined proof; no capability PR has been created.

### Earlier completion investigation (historical)

The handwritten wrapper `845b0c2a` first failed parsing the illegal explicit
`response_buffering: "none"` value. Independently reviewed `7721e5be` uses the
legal omission/default None. Clang Release build and formatting passed, but its
public O2/io_uring run failed once in 2.42s at the joint ledger/retirement gate
(access log empty). Exact prefix, Open probe and inactivity EOF passed the
capture's earlier checks; this is not complete capability acceptance. Both full
logs/source and reproduction are preserved in [#640](https://github.com/hurricane1026/Rut/issues/640),
linked to #638/#271. Investigate ordinary runtime completion ownership; do not
rerun unchanged, weaken the ledger/timing gates, or begin converter admission.
Local evidence: `/tmp/rut-638-capability-first.log`,
`/tmp/rut-638-capability-none-first.log`, and
`/tmp/rut-638-capability-none-build.log`. No runtime fix has been applied yet.
Reviewed diagnostic `d6ff3bdd` built successfully, but its first run failed at
the earlier EOF/wire gate (2.16s); `/tmp/rut-640-diagnostic-first.log` and full
#640 comment `5650166323` preserve it. Reviewed `e9f78b52` adds EOF rejection clocks and built successfully. Its first
run failed the joint gate with clear retirement Ready/count1, EOF at publication
+1999.722453ms, retirement +1999.762588ms, and zero access bytes in the last
sample at EOF+247.512583ms (`/tmp/rut-640-eof-diagnostic-first.log`). Natural
retirement is therefore present; missing completion publication is confirmed.
None's coarse timer wheel is also at the upper timing boundary; resolve precision
without relaxing gates. Next implement/review the generic completion fix and its
ownership controls, then address timing before full capability acceptance.

### Accepted oracle and wrapper context

The minimal fixture uses one server/location, numeric loopback endpoints,
`proxy_buffering off`, `proxy_read_timeout 1s`, and an owned access ledger.
A fresh bodyless HTTP/1.1 GET has 60 request bytes. The origin publishes one
103-byte response prefix with `Content-Length: 12` but only `hello`, then remains
open and silent until natural peer retirement. The first local run of `d345e933` observed the exact normalized 127-byte client
prefix, inactivity EOF, one natural retirement and stable `60\n` ledger. The
Clang Release build and six focused tests passed with zero skips (16.65s, new
oracle 1.65s); logs are `/tmp/rut-638-snapshots-build.log` and
`/tmp/rut-638-snapshots-targeted.log`. This is local nginx-only evidence; the
shared validator/negative controls are now implemented in `247338de`;
complete-candidate CI passed: run `34730518730`, all 14 ordinary jobs and
required nginx 162/162, zero skips, 717.96s. #639 merged as `ed0eec96`; log
`/tmp/rut-639-f2b1-nginx-ci.log`. This completes only the nginx-only oracle.

### Completed implementation: snapshots and ownership only (`d345e933`)

- Remove reads/copies of live recorder request/history vectors before join.
  Freeze owned observations and atomics while live; inspect vectors after join.
- Read recorder-local shutdown/close, terminated-thread and closed-listener
  cleanup facts only after join. They cannot establish natural retirement.
- Start joint retirement/access-ledger observation immediately after actual
  downstream EOF, without a separate one-second retirement wait.
- Require joint readiness before EOF + 250 ms, followed by 175 ms stable
  custody. Take one fresh coherent retirement snapshot for every sample,
  including the final sample; reject duplicates or invalid live evidence.
- Use actual publication and probe-ACK timestamps, not the fixed 1e9 clock
  anchor. Preserve prefix < 800 ms, probe ACK within 100 ms, and EOF and observed
  retirement each in [750 ms, 2000 ms) from publication. Both follow probe ACK;
  do not impose an ordering between EOF and observed retirement.
- Preserve the fresh recorder-owned Open probe after the full prefix and
  downstream EOF/tail/liveness checks while waiting and after ACK.
- Reviewer claimed that the probe branch was unreachable; the primary agent's
  control-flow inspection disputed this. Recheck the enclosing independent
  conditionals before changing branch selection. This is not a confirmed bug.

The bounded correction above is implemented and independently reviewed. The
first review requested explicit EOF-after-ACK, full post-ACK custody and final
ledger-read-before-retirement-snapshot ordering; these were fixed before commit.
The shared ledger observer was also moved unchanged before its first use to
correct the predecessor's declaration-order error. No parser/converter/runtime
expansion occurred. Consult current status for lead-scheduled validation; this
increment alone does not accept the complete oracle.

### Completed shared validator/control increment (`247338de`)

Owned early/final wire and frozen clocks/counts/custody/ledger state enter one
`validate_explicit_off_observation` in both the real pre-cleanup path and the
synthetic self-check. Named negative controls cover wire/ACK/retirement/ledger
failures, exact timing boundaries and real observer failure/restoration. The
standalone CTest `test_nginx_issue638_explicit_off_observation_self_check` needs
no Docker; the real oracle runs the same controls before its episode. Luna
implemented, the lead corrected remaining control arithmetic under the prior
fallback authorization, and a different Luna independently approved the final
diff. Clang Release build and seven focused tests passed, zero skips: standalone
self-check 0.01s, six regressions 16.40s (new real oracle 1.68s). Logs are
`/tmp/rut-638-validator-build.log`, `/tmp/rut-638-validator-self-check.log` and
`/tmp/rut-638-validator-targeted.log`. This does not establish an ordinary-RUT
capability or converter admission.

## NEXT

1. Independently review and validate the actual same-file converter-stdout pair.
2. Complete normal/required CI and integrate only into converter integration.
3. Update only the exact proven scope and resolve #638.

The bounded `proxy_buffering off` model/lowering is locally validated.
Parser and generated-source tests are not paired runtime behavioral proof. Do not declare SUPPORTED
until the precise supported input scope has actual equivalence evidence.

## Testing and issue discipline

- Lead is sole heavy-test scheduler; only one full build/integration/differential
  run at a time. Use `-j1` for the existing build.
- Existing build directory: `/home/hurricane/private/code/Rut_build627_clang`
  (Clang Release, IPO off). It was rebuilt for `247338de` in this session;
  recheck its source/cache before later reuse.
- Target: `test_nginx_differential`. New oracle mode:
  `--pinned-nginx-explicit-buffering-off-oracle`. Inspect registered CTest names
  and required environment before invoking tests.
- Pinned nginx image:
  `nginx@sha256:1854da86e82d5dfb49a8f3d78b099adcc7e36608b207146ed95cd47937938a40`.
- Preserve failing logs. Do not widen timing gates, skip evidence, waive failed
  CI, or rerun unchanged failures merely to obtain green.
- Converter gaps become bounded converter tasks. RUT expressiveness gaps
  become linked `[rut-capability]` issues with minimal nginx example, expected
  behavior, current limitation, required general primitive and acceptance test.
- #632's historical Docker timeout cause remains unresolved, but was not the
  current implementation blocker. Check issues before creating duplicates.

## Paste into the new session

```text
Use Astra as architect/lead and Luna workers for implementation.
Continue nginx.conf → ordinary RUT source conversion, not runtime nginx.conf support.
Work in /home/hurricane/private/code/Rut_issue627_two_second_oracle.
Read applicable AGENTS.md and docs/nginx-converter-session-handoff.md first,
then .nginx-converter-status.md, docs/nginx-compatibility.md and issue #638.
Verify git/GitHub state and preserve unrelated user WIP in the main worktree.
The audit, snapshots/ownership and shared validator/controls are complete.
The nginx-only candidate passed complete CI and merged as ed0eec96.
Shared capture d9e1733a passed independent review, Release build and 7/7 tests.
The dedicated ordinary-RUT capability passed full CI and merged as f08b85ba.
Bounded Off model/provenance/lowering a2358195 passed independent review and
parser/CLI validation. Next finish the actual converter-stdout pair.
Proceed with one small implementation → different-worker review →
lead-scheduled tests → status/issue update at a time. Do not claim off support
from untested source or nginx-only evidence. Keep parent PR #269 draft and
integrate only into agent/nginx-to-rut-converter, not main.
```
