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
- Branch: `nginx-off-capability`, based on accepted #639 merge `ed0eec96`.
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

## CURRENT: #640 ordinary-RUT None inactivity finalization

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

1. Implement and independently review the generic #640 completion fix with
   meaningful ownership controls; lead-run the unchanged ordinary-RUT witness.
2. Complete capability candidate normal/required CI and integrate only into
   `agent/nginx-to-rut-converter` after proof.
3. Only after capability is proven, implement bounded off model/lowering and an
   actual same-file nginx-versus-generated-RUT differential pair.

`proxy_buffering off` is still rejected by the converter. Candidate runtime
paths from a source audit are not behavioral proof. Do not declare SUPPORTED
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
Next finish the dedicated ordinary-RUT public capability witness.
Proceed with one small implementation → different-worker review →
lead-scheduled tests → status/issue update at a time. Do not claim off support
from untested source or nginx-only evidence. Keep parent PR #269 draft and
integrate only into agent/nginx-to-rut-converter, not main.
```
