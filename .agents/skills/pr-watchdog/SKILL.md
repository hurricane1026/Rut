---
name: pr-watchdog
description: 持续监控一个或多个 GitHub PR，处理 review、CI 与 rebase，直至达到终态。适用于用户要求 babysit、monitor 或持续推进 PR。
---

# PR Watchdog（Python 轮询）

将 PR 标识解析为 `owner/repository#number` 后，**必须由 Python 轮询器负责轮询**，而不是由代理依据英文提示自行等待或轮询。启动方式如下；状态文件必须在所有 worktree 外：

```bash
python3 .agents/skills/pr-watchdog/scripts/poll_prs.py <PR...> \
  --state-file /tmp/pr-watchdog/<watch-id>/poll-state.json
```

轮询器每分钟输出一条 JSON Lines `changed` 事件；它会持久化指纹、仅报告实质变化，并持续轮询所有非终态 PR。以 `--once` 可做一次健康检查。协调代理读取这些事件并安排工作；未变化、等待中的 CI 或 review 不是完成条件。Python 脚本只读取 GitHub 元数据，绝不执行 PR 代码。

要让事件真正触发协调代理，必须同时配置 `--on-change-command`。该命令接收一条 JSON 事件（stdin），应当是一个快速、幂等的持久队列操作，而不是长时间运行的修复任务。例如，先启动一个持久 Codex 协调会话，再用：

```bash
python3 .agents/skills/pr-watchdog/scripts/poll_prs.py <PR...> \
  --state-file /tmp/pr-watchdog/<watch-id>/poll-state.json \
  --on-change-command 'python3 .agents/skills/pr-watchdog/scripts/dispatch_codex.py --thread <coordinator-thread>'
```

`poll_prs.py` 会在事件输出后调用该命令；命令失败会产生 `dispatch_error` 事件而不会停止轮询。这样 agent turn 结束或聊天界面暂时没有活动时，新的 review/CI 变化仍会进入持久会话队列，而不是只留在无人消费的 stdout 中。不要把修复逻辑直接放进轮询器，也不要让 hook 执行来自 PR 的代码。

Drive every named PR toward a reviewed, green, mergeable state and keep watching until each reaches a terminal condition. Invocation with one or more PRs identifies their external branches, review threads, CI runs, and PR comments as in scope; it does not authorize merging a PR or changing unrelated resources.

Continuous monitoring is the default behavior. A bare invocation containing only `$pr-watchdog` and one or more numeric PR/issue numbers means to start the full watch loop and continue until the normal terminal conditions; never require the user to supply URLs or repeat "continuously monitor," "until merged," or the workflow details.

## Team roles

使用协调代理、Sol 审查者及受限的 Luna 工作者：

- 先启动一个长驻 `gpt-5.6-sol`。Sol 只检查轮询事件、诊断、每个修复 diff 和测试证据，并决定批次是否可推送；不得编辑文件或推送。
- 对可行动 PR 只启动 `gpt-5.6-luna` 工作代理。Luna 在自己独立 checkout 中完成调查、反馈验证、改代码、格式化、测试、提交和解决 rebase 冲突；同一 head 同时只能有一个 Luna 修改。
- 协调代理拥有脚本生命周期、事件分发、GitHub 写操作、调度和最终报告。把完整 watch 集摘要交给 Sol；Luna 只接收自己的 PR、checkout、仓库规则和当前证据。Sol 未审阅实际 diff 与验证结果前，不得推送。
- Respect the available agent-slot limit. Keep monitoring every PR even when there are fewer worker slots than actionable PRs; queue repair batches fairly and expose which PRs are queued. Sol reviews ready batches sequentially when necessary.
- Do not push a repair batch until Sol has reviewed the actual diff and validation results. If Sol rejects it, send the concrete findings back to the assigned worker and repeat.

## Establish the watch

### Single-instance requirement (mandatory)

Never run two `poll_prs.py` processes for the same canonical PR/watch-id or
state file. Before starting a watcher, inspect the process table with an
exact-argument match covering `poll_prs.py`, the exact PR list, and the exact
`--state-file`. If one matching process exists, reuse it and do not start
another. If duplicates exist, record their PIDs, terminate only those exact
duplicate watcher processes, verify they exited, and then start exactly one
replacement. Never use broad `pkill python3` or a pattern that can match the
watcher's own command. Keep one durable state file per watch-id outside all
worktrees, and reconcile an existing watcher before launching a new one.

1. Resolve the PR set from the user's identifiers. For a bare numeric ID such as `10159`, derive `owner/repository` from the current checkout with `gh repo view`, then resolve the canonical PR URL with `gh pr view <ID> --repo <owner/repository>`; all bare IDs in one invocation belong to that current repository. Accept `owner/repository#123` when the user needs a different repository, and continue accepting full PR URLs. If there is no unambiguous current GitHub repository, ask only for the repository once rather than requesting full URLs. Canonicalize each PR as `owner/repository#number` and reject accidental duplicates. Use GitHub GraphQL/API data to record each repository, PR number, base branch, head repository and branch, head SHA, state, merge state, reviews, unresolved review threads, comments, and checks. Verify authentication and write access per head repository before attempting mutations, resolve the authenticated GitHub actor login, and persist that identity for later comment-authorship checks.
2. Read each repository's applicable `AGENTS.md` files. Preserve all existing work by creating one dedicated temporary worktree or clone per PR head; never take over or clean the user's current worktree. Never share a checkout between PRs. In a detached checkout, push explicitly to the verified head branch.
3. Start one persistent goal for the watch set. Maintain an independent state record per canonical PR, including its checkout, agent assignment, pending work, terminal state, and a ledger keyed by review thread/comment/check IDs, submitted review IDs plus head/commit context, and head SHA. Record each submitted review's disposition and reply evidence for resume deduplication. Keep the state and transactional outbox in a durable location outside every tracked worktree, and namespace all cached state by canonical PR so events and `@codex review` comments cannot be confused across PRs.
4. 启动 Sol，然后为可行动 PR 分配 Luna 工作者；任何工作代理变更前，先向 Sol 发送完整的初始 watch 状态。

If a PR comes from a fork, resolve a writable remote for its actual head repository. Mark only that PR blocked and continue servicing the others rather than pushing to a similarly named branch in the base repository.

Before executing any PR-controlled build, test, or script for a fork, external, or otherwise untrusted head, explicitly confirm trust or run it in a sandbox with no secrets/credentials and restricted filesystem, process, and network access; an ordinary temporary worktree is not a sandbox. Default to fail-closed when neither condition is met. Untrusted PRs may still receive GitHub metadata/read-only review, but remain per-PR execution blockers; never expose `gh` or `git` credentials to their code.

## Multiple-PR isolation and scheduling

- Poll all non-terminal PRs on every watch cycle before scheduling repair work. Do not let a long build, pending review, or blocked PR prevent state refreshes for the others.
- Apply the reconciliation priority below independently within each PR. Across PRs, prefer already-started repair batches, then the oldest unhandled actionable event; avoid starving a quiet PR because another receives frequent events.
- Treat all watched PRs sharing `head repository + head branch` as one mutation unit: serialize their pushes, rebases, replies, and resolutions, and refresh every member after each mutation. Before scheduling or performing a rebase for any member, discover and query every open PR in GitHub sharing that head repository and ref, including PRs omitted from the watch invocation, and add their base repository/branch refs to the group's comparison. Use a query that is valid for the installed `gh` version (for example, `number,headRefName,headRepository,baseRefName,baseRefOid`); a failed field selection is a tool error, not evidence of an unsafe shared branch. Retry discovery once through GraphQL before blocking. If discovery succeeds and finds exactly one open PR, or finds multiple PRs whose base repository/ref are identical and compatible, automatic rebase is allowed. Only if discovery still fails, or any bases differ or are incompatible, mark the shared group rebase-blocked, do not auto-rebase or assign workers to oscillating rebases, and require the user to choose a canonical base or split the branches; continue safe non-rebase work for the group.
- Keep build directories, temporary files, ports, and test processes isolated. Schedule resource-heavy tests rather than oversubscribing the host when repository guidance or machine limits require it.
- A failure or blocker belongs to one PR unless evidence shows a shared cause. Continue useful work on unaffected PRs and report status using canonical PR identities.

### Worker timeout and recovery

- Every assigned Luna repair or rebase task must record `started_at`, `deadline`, and the target agent in the durable per-PR state. The hard deadline is 20 minutes after assignment unless the coordinator explicitly records a shorter deadline for a bounded check.
- The persistent Sol reviewer is exempt from this worker deadline; its health is tracked separately. The timeout applies to a Luna task that has not returned a result, not to a task that is actively reporting progress at a coordinator checkpoint.
- On or after the deadline, refresh collaboration-agent status and confirm the exact target is still running before acting. Interrupt only that target agent (never the watcher, Sol, or another PR's worker), record a `timed_out` disposition with the last known task/commit state, and re-dispatch the same task once with the preserved worktree and evidence.
- Do not start a second Luna for the same PR/head while the original target is still running, and do not discard its worktree or uncommitted changes. After a timeout interrupt, the replacement must re-check the remote head and current worktree before editing.
- A re-dispatch gets a fresh 20-minute deadline and an incremented attempt number. Repeated timeouts remain actionable and must be reported; they do not authorize a push, review request, merge, or broad process termination.

## Reconciliation loop

On every cycle, refresh each non-terminal PR rather than relying on previously fetched state. Reconcile each PR in this priority order:

1. newly submitted reviews, unresolved review threads, and newly arrived top-level PR Conversation comments;
2. failed or cancelled required checks;
3. an out-of-date or conflicting head that prevents merging;
4. pending checks/reviews and newly arriving events.

Coalesce related findings for the same PR into one repair batch when practical; never combine commits for different PR heads. Continue monitoring after each batch; a quiet poll or a pending CI run is not completion. Use a watch/wait facility when available, otherwise poll with a bounded interval of about 60 seconds and remain responsive to the user.

### Review-request wait state

- A posted `@codex review` is a request, not evidence that review is complete. After each request, enter an `awaiting_review` state recording the canonical PR, candidate SHA, request comment ID/time, and a deadline.
- For at least one bounded wait window (10 minutes unless the repository's review service documents a different SLA), refresh every watched non-terminal PR about once per minute. Each poll must fetch the complete reviews and review-thread connections, not only summary status.
- `poll_prs.py` identifies a completion generation by the trusted Codex summary comment ID, its `updatedAt`, and the candidate SHA; it must not infer request identity from arbitrary exact-body comments. The coordinator binds that generation to the request comment ID/time recorded in its transactional outbox and accepts it only when the trusted summary update is later than that request. Leave `awaiting_review` only after the poller emits the persisted `review_completion_audit` event on a later poll that re-fetched the complete review-thread connection. Do not close the wait in the same metadata fetch that first observes `Completed`: findings can become visible shortly after the summary transition. The poller must dispatch this audit independently of an ordinary `changed` event in that poll, whether the fingerprint stayed stable or changed, retry only the event whose dispatch failed, and defer terminal retirement when completion and merge/close are first observed together until the final audit succeeds. Every actionable thread found by the follow-up audit must have a disposition, evidence reply, and explicit resolution. A pending wait must not stop polling unrelated PRs.
- If the candidate-specific summary has not completed at the deadline, record a review-service timeout and continue polling without posting another request for that same PR/SHA. The one-request-per-PR/SHA invariant is strict: a second trigger is allowed only for a genuinely indeterminate initial POST after a fresh exact-comment deduplication check, including authenticated author identity, shows that no request was persisted, never merely because the wait deadline elapsed. A new request requires a new candidate SHA (normally after a repair push) or an explicit external retry token. If the service returns an `Unknown`/environment error, classify it as an environment blocker and keep the existing request ledger entry; do not create a duplicate trigger.

### Review feedback

- Fetch review threads, their comments, resolution state, authors, file positions, and commit context. Treat unresolved inline threads as actionable even if the overall review state is not `CHANGES_REQUESTED`.
- Fetch every submitted review's full body, including body-only reviews, and classify it by review ID plus the head/commit context it reviewed. Route each classification through the worker/Sol disposition workflow and persist its disposition and reply evidence in the durable ledger so multiple reviews on one head remain distinct across resume. Inline findings use the normal thread reply/resolve mutations; body-only or general reviews receive one PR Conversation reply explicitly naming the review ID and URL, with no resolve mutation.
- Never infer that a review has no findings from its summary text or from a green/clean PR. After every review request, CI transition, polling cycle, and before declaring a non-terminal PR blocked or terminal, re-fetch the complete review-thread connection and process every newly observed unresolved thread, including threads created after the prior audit. A review is handled only when each of its actionable thread IDs has a recorded change/no-code disposition, an evidence reply, and (for inline threads) an explicit resolved state.
- 让分配的 Luna 工作者根据当前代码验证每条建议。实施有效反馈并新增或更新聚焦测试；对错误、过期或互相冲突的反馈，准备简明、基于证据的回复，而非有害改动。
- Have Sol review the complete batch and its test evidence. Once approved, commit and push any warranted changes, and record a no-code disposition for each concern answered without a change.
- Retire terminal PRs before scheduling new-thread work: if a PR is merged or closed, cancel pending outbox entries and record any later review threads as terminal observations. Do not reopen it, push to it, request review, or require a repair/reply/resolution loop for code that can no longer change. A safe informational reply may be recorded only when explicitly needed by the service, but terminal state must remain terminal.
- Immediately before every repair push, freshly refresh the state of every affected watched non-terminal PR. If any affected PR is merged or closed, abort before pushing, atomically cancel the corresponding outbox entries (or the entire shared-head batch when they share a push), post no review requests, and return to reconciliation. This state check is required in addition to, not replaced by, the remote head and expected-SHA checks below.
- Immediately before every repair push, refresh the remote head and require it to equal the batch's recorded expected SHA. For a non-rewrite repair, verify that the candidate repair commit descends from that expected head; for an intentional rebase rewrite, verify that its input was built from that exact expected head. Then push with an atomic explicit expected-SHA lease (for example, `--force-with-lease=refs/heads/<head-ref>:<expected-sha>`). On any mismatch or failed lease, refresh and reconcile; never override the remote or silently reinstate a contributor reset.
- After any required push, reply to each handled thread according to its disposition: for a change, explain what changed and include the pushed commit SHA; for no-code, provide the evidence-based rationale. A wholly no-code batch needs no commit or push. Resolve each thread only after its concern is addressed or conclusively answered.
- After every watchdog-performed push, including a repair push or rebase, apply the transactional review-request outbox and post exactly one deduplicated PR-level comment whose entire body is `@codex review` for the new SHA on every affected watched PR sharing that head, not only the PR that initiated the batch. This explicit request is mandatory even if automatic review is enabled, a push event appears to have started a review, or a matching-head Codex review already exists. Never post it for a no-code disposition or repeat it for the same PR and SHA.

Use GitHub's review-thread reply and resolve mutations for inline threads; a general PR comment is not a substitute for a thread reply.

### Top-level conversation comments

- Fetch new top-level PR Conversation comments on every reconciliation cycle and classify each as actionable feedback, status/informational text, or a bot/automation command. Queue actionable comments through the same worker/Sol workflow, and reply once with the disposition and evidence after handling; record the comment ID in the per-PR ledger. Record status or bot comments as observed/ignored according to their type, without enqueueing or auto-replying solely because of them, so they do not create repair or reply loops. Top-level comments have no resolve mutation; never attempt to resolve them.

### Transactional review-request outbox

- Keep a durable per-watch outbox outside the tracked worktree. Before every watchdog-performed push, persist pending review-request entries for every affected watched PR, each containing the canonical PR, shared head repository/ref, recorded expected old SHA, candidate new SHA, authenticated request-author login, and a creation timestamp. Persist the complete set atomically before attempting the push; do not post review requests before the push succeeds.
- After a successful push, refresh the remote head and atomically record verified push completion (`candidate_visible_at`) with the observed candidate SHA before fulfilling any pending entry. For each affected watched PR, inspect exact `@codex review` comments created after both that entry's timestamp and `candidate_visible_at`, and accept only a comment authored by the authenticated request actor recorded in the outbox. A comment created before the candidate became remote-visible or by any other participant is not proof for that candidate. A matching-head automatic or submitted Codex review is useful status evidence but never substitutes for the mandatory explicit request. If no qualifying authenticated comment exists, post one; when the POST returns, atomically record its returned comment ID and completion, and never duplicate an existing request for the same PR and SHA. If the POST times out or returns an indeterminate result, leave the entry pending and re-fetch comments matching the exact body, timestamp gates, and recorded author before any retry; never blindly retry the POST.
- On resume and every reconciliation cycle, replay pending entries by inspecting the outbox, remote head, verified completion/candidate-visible timestamp, persisted POST result comment ID when available, and authenticated exact post-timestamp `@codex review` comments. If the candidate is still the remote head but completion was not recorded, verify that fact and atomically record a fresh `candidate_visible_at` before evaluating evidence. Mark the entry complete only from the persisted POST result or a freshly fetched exact comment whose author equals the recorded request actor; ignore identical comments from all other authors. Post only a genuinely missing request whose candidate SHA is still the remote head, and only after a fresh authenticated evidence fetch confirms it is missing. A matching-head submitted or automatic review does not complete the request outbox. If the push failed, the expected-head check or lease failed, or the candidate is no longer current, atomically transition the entry to terminal `stale`/`cancelled` with the reason and observed head before refreshing or reconciling the batch, so it cannot replay forever or contaminate a later batch.

### CI failures

- Inspect the failing check annotations and logs, including the failing command and the first causal error. Distinguish code failures from infrastructure failures, cancellations, and known flakes.
- 对代码失败，把完整证据交给分配的 Luna 工作者：尽可能本地复现，做最小修复，并运行聚焦测试和仓库要求的构建/格式化检查。提交和推送前 Sol 必须批准 diff 与证据。
- For a transient infrastructure failure or demonstrated flake, rerun only the affected check when permitted and record why no code changed. Do not create empty commits to restart CI.
- After any new fix push, comment `@codex review` once for that head SHA as described above, then watch both the candidate-specific Codex Review Summary and the new checks.

### Rebase when merge is blocked

Treat the shared `head repository + head branch` group as the mutation unit for rebases. Before any rebase, discover and query every open PR in GitHub sharing that head repository and ref, including PRs omitted from the watch invocation, and record every member's base repository/branch ref. Retry discovery once through GraphQL if the first `gh` query fails. A successfully discovered single-PR group, or a group whose members all have the same compatible base repository/ref, may be rebased automatically. If discovery still fails, or the bases differ or are incompatible, mark the group rebase-blocked and stop all automatic rebasing until the user chooses a canonical base or splits the branches; workers must not bypass this guard or oscillate between bases. Continue safe non-rebase work while the group is blocked.

Derive the base branch from PR metadata; never assume its name. Rebase when the head is behind or has conflicts and that condition is what prevents merging. A `BLOCKED` state caused only by required reviews or CI is not a reason to rewrite history.

Before rebasing, fetch the exact base and head refs and record the expected remote head SHA. The assigned Luna worker performs the rebase and resolves conflicts, then runs tests covering the resolved areas. Sol reviews the rebased range, conflict resolutions, and results. Immediately before pushing the rewrite, freshly refresh every affected watched PR; if any is merged or closed, abort the push, atomically cancel the corresponding or entire shared-head outbox batch, post nothing, and return to reconciliation. Then refresh the remote head and require it still equals that expected SHA; verify the rebase input was built from that exact expected head, then use an atomic explicit expected-SHA lease (`--force-with-lease=refs/heads/<head-ref>:<expected-sha>`). If the head or lease mismatches, refresh state and reconcile; never bypass or override it. After a successful rebase push, use the same outbox and shared-head fanout rules for the resulting new SHA.

## Safety and completion

- Follow repository-specific build, test, formatting, concurrency, and ownership rules. Keep changes limited to the PR's purpose and preserve unrelated commits.
- Never merge, close, approve, or enable auto-merge unless the user explicitly asks. Do not resolve a thread merely to make the counters green.
- Report significant transitions while working: repair ready, push completed, CI diagnosis, rebase completed, and genuine blockers. Avoid noisy reports for unchanged polls.
- Retire an individual PR when it is merged or closed, while continuing to watch the remaining PRs; late review events must not resurrect it. Finish successfully when every PR is retired or the user explicitly ends the whole watch. If a PR becomes green, approved, and mergeable but remains open, report that state and keep watching it.
- Treat missing credentials/permissions, an inaccessible fork branch, or a decision requiring new user authority as a per-PR blocker. Exhaust safe read-only diagnosis first. Continue other PRs, and do not silently abandon the blocked one after a failed attempt.
