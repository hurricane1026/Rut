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
- Branch: `nginx-off-oracle`.
- This session started with clean worktree and local/remote HEAD both
  `6942666557d9f9a4303d40de266b640f4920f217`.
- Current #638 source candidate: `247338de`, independently **APPROVED for the
  shared-validator/control increment**, following the accepted snapshots fix
  `d345e933`. See current status for validation logs and the explicit primary
  implementation fallback used for final control corrections. Historical
  rejected candidates/reviews remain evidence. Complete-candidate PR/normal CI
  remains the next task.
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

## CURRENT: #638 complete nginx-only oracle candidate review/normal CI

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
complete-candidate CI remains pending.

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

1. Review and validate the complete nginx-only candidate through normal CI in
   a PR targeting `agent/nginx-to-rut-converter`. Preserve rejected review
   evidence and any failed run; do not promote compatibility from nginx alone.
2. After review and nginx-only oracle validation, establish the exact behavior
   through a separate ordinary-RUT `None` buffering capability witness.
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
Next review and validate the complete nginx-only candidate through normal CI.
Proceed with one small implementation → different-worker review →
lead-scheduled tests → status/issue update at a time. Do not claim off support
from untested source or nginx-only evidence. Keep parent PR #269 draft and
integrate only into agent/nginx-to-rut-converter, not main.
```
