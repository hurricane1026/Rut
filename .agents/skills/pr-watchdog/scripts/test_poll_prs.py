#!/usr/bin/env python3
"""Focused tests for poll_prs.py state-file safety checks."""

import importlib.util
import io
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).with_name("poll_prs.py")
SPEC = importlib.util.spec_from_file_location("poll_prs", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
poll_prs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(poll_prs)


def connection(nodes, has_next_page=False, end_cursor=None):
    return {
        "nodes": nodes,
        "pageInfo": {"hasNextPage": has_next_page, "endCursor": end_cursor},
    }


def completed_review_summary():
    return {
        "state": "OPEN",
        "head_sha": "abcdef0123456789",
        "comments": [
            {
                "author": {"login": "hurricane1026"},
                "body": "@codex review",
                "createdAt": "2026-08-30T17:07:29Z",
                "updatedAt": "2026-08-30T17:07:29Z",
            },
            {
                "id": "summary-comment",
                "author": {"login": "chatgpt-codex-connector"},
                "body": (
                    f"{poll_prs.CODEX_REVIEW_SUMMARY_MARKER}\n"
                    "| ✅ **Completed** | `abcdef0` | Manual request |"
                ),
                "createdAt": "2026-08-30T16:25:35Z",
                "updatedAt": "2026-08-30T17:10:33Z",
            },
        ],
    }


class StatePathValidationTest(unittest.TestCase):
    def test_rejects_path_inside_known_worktree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            worktree = Path(temporary) / "checkout"
            worktree.mkdir()
            with self.assertRaisesRegex(ValueError, "outside git worktrees"):
                poll_prs.validate_state_path(worktree / "state.json", [worktree])

    def test_accepts_path_outside_known_worktrees(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            worktree = root / "checkout"
            state = root / "state" / "poll-state.json"
            worktree.mkdir()
            self.assertEqual(poll_prs.validate_state_path(state, [worktree]), state.resolve())


class PollingLifecycleTest(unittest.TestCase):
    def test_dispatch_event_sends_json_to_coordinator(self) -> None:
        event = {"event": "changed", "pr": "owner/repository#7", "data": {"head_sha": "abc"}}
        completed = subprocess.CompletedProcess(["coordinator"], 0, "", "")
        with mock.patch.object(poll_prs.subprocess, "run", return_value=completed) as run:
            poll_prs.dispatch_event("coordinator --enqueue", event)
        self.assertEqual(run.call_args.args[0], ["coordinator", "--enqueue"])
        self.assertEqual(run.call_args.kwargs["input"], poll_prs.json.dumps(event, ensure_ascii=False) + "\n")
        self.assertEqual(run.call_args.kwargs["timeout"], poll_prs.DISPATCH_TIMEOUT_SECONDS)

    def test_dispatch_failure_is_reported(self) -> None:
        completed = subprocess.CompletedProcess(["coordinator"], 3, "", "queue unavailable")
        with mock.patch.object(poll_prs.subprocess, "run", return_value=completed):
            with self.assertRaisesRegex(RuntimeError, "dispatch command exited 3"):
                poll_prs.dispatch_event("coordinator", {"event": "changed"})

    def test_empty_dispatch_command_is_rejected(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "dispatch command is empty"):
            poll_prs.dispatch_event("   ", {"event": "changed"})

    def test_failed_terminal_dispatch_is_not_retired(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "poll-state.json"
            with (
                mock.patch.object(sys, "argv", [
                    "poll_prs.py", "owner/repository#7", "--once", "--state-file", str(state_path),
                    "--on-change-command", "coordinator",
                ]),
                mock.patch.object(poll_prs, "validate_state_path", return_value=state_path),
                mock.patch.object(poll_prs, "query_pr", return_value=object()),
                mock.patch.object(poll_prs, "summary", return_value={"state": "MERGED"}),
                mock.patch.object(poll_prs, "dispatch_event", side_effect=RuntimeError("queue unavailable")),
            ):
                self.assertEqual(poll_prs.main(), 1)
            saved = poll_prs.load_state(state_path)["prs"]["owner/repository#7"]
            self.assertFalse(saved["terminal"])
            self.assertIsNone(saved["fingerprint"])

    def test_restart_skips_previously_retired_pr(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "poll-state.json"
            poll_prs.save_state(state_path, {"prs": {"owner/repository#7": {
                "fingerprint": "terminal", "terminal": True, "terminal_state": "MERGED",
            }}})
            with (
                mock.patch.object(sys, "argv", [
                    "poll_prs.py", "owner/repository#7", "--once", "--state-file", str(state_path),
                ]),
                mock.patch.object(poll_prs, "validate_state_path", return_value=state_path),
                mock.patch.object(poll_prs, "query_pr") as query_pr,
            ):
                self.assertEqual(poll_prs.main(), 0)
            query_pr.assert_not_called()

    def test_once_reports_errors_after_polling_and_saving_other_prs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "poll-state.json"
            output = io.StringIO()
            with (
                mock.patch.object(sys, "argv", [
                    "poll_prs.py", "owner/repository#1", "owner/repository#2", "--once",
                    "--state-file", str(state_path),
                ]),
                mock.patch.object(poll_prs, "validate_state_path", return_value=state_path),
                mock.patch.object(
                    poll_prs, "query_pr",
                    side_effect=[RuntimeError("gh command timed out after 30 seconds"), object()],
                ) as query_pr,
                mock.patch.object(poll_prs, "summary", return_value={"state": "OPEN"}),
                redirect_stdout(output),
            ):
                self.assertEqual(poll_prs.main(), 1)
            self.assertEqual(query_pr.call_count, 2)
            self.assertEqual(output.getvalue().count('"event": "poll_error"'), 1)
            self.assertIn("owner/repository#2", poll_prs.load_state(state_path)["prs"])

    def test_dispatches_follow_up_audit_when_completed_review_is_unchanged(self) -> None:
        completed = completed_review_summary()
        merged = dict(completed, state="MERGED")
        dispatched = []
        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "poll-state.json"
            with (
                mock.patch.object(sys, "argv", [
                    "poll_prs.py", "owner/repository#7", "--interval", "0.01",
                    "--state-file", str(state_path), "--on-change-command", "coordinator",
                ]),
                mock.patch.object(poll_prs, "validate_state_path", return_value=state_path),
                mock.patch.object(poll_prs, "query_pr", return_value=object()),
                mock.patch.object(poll_prs, "summary", side_effect=[completed, completed, merged]),
                mock.patch.object(
                    poll_prs, "dispatch_event", side_effect=lambda _command, event: dispatched.append(event),
                ),
                mock.patch.object(poll_prs.time, "sleep"),
            ):
                self.assertEqual(poll_prs.main(), 0)

        self.assertEqual(
            [event["event"] for event in dispatched],
            ["changed", "review_completion_audit", "changed"],
        )
        self.assertEqual(dispatched[1]["head_sha"], completed["head_sha"])

    def test_dispatches_follow_up_audit_alongside_metadata_change(self) -> None:
        completed = completed_review_summary()
        changed = dict(completed, merge_state_status="BLOCKED")
        merged = dict(changed, state="MERGED")
        dispatched = []
        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "poll-state.json"
            with (
                mock.patch.object(sys, "argv", [
                    "poll_prs.py", "owner/repository#7", "--interval", "0.01",
                    "--state-file", str(state_path), "--on-change-command", "coordinator",
                ]),
                mock.patch.object(poll_prs, "validate_state_path", return_value=state_path),
                mock.patch.object(poll_prs, "query_pr", return_value=object()),
                mock.patch.object(poll_prs, "summary", side_effect=[completed, changed, merged]),
                mock.patch.object(
                    poll_prs, "dispatch_event", side_effect=lambda _command, event: dispatched.append(event),
                ),
                mock.patch.object(poll_prs.time, "sleep"),
            ):
                self.assertEqual(poll_prs.main(), 0)

        self.assertEqual(
            [event["event"] for event in dispatched],
            ["changed", "changed", "review_completion_audit", "changed"],
        )

    def test_retries_follow_up_audit_after_dispatch_failure(self) -> None:
        completed = completed_review_summary()
        merged = dict(completed, state="MERGED")
        dispatched = []

        def dispatch(_command, event):
            dispatched.append(event)
            if event["event"] == "review_completion_audit" and sum(
                item["event"] == "review_completion_audit" for item in dispatched
            ) == 1:
                raise RuntimeError("queue unavailable")

        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "poll-state.json"
            with (
                mock.patch.object(sys, "argv", [
                    "poll_prs.py", "owner/repository#7", "--interval", "0.01",
                    "--state-file", str(state_path), "--on-change-command", "coordinator",
                ]),
                mock.patch.object(poll_prs, "validate_state_path", return_value=state_path),
                mock.patch.object(poll_prs, "query_pr", return_value=object()),
                mock.patch.object(
                    poll_prs, "summary", side_effect=[completed, completed, completed, merged],
                ),
                mock.patch.object(poll_prs, "dispatch_event", side_effect=dispatch),
                mock.patch.object(poll_prs.time, "sleep"),
            ):
                self.assertEqual(poll_prs.main(), 0)

        self.assertEqual(
            [event["event"] for event in dispatched],
            ["changed", "review_completion_audit", "review_completion_audit", "changed"],
        )

    def test_terminal_pr_waits_for_completion_audit_before_retirement(self) -> None:
        terminal = dict(completed_review_summary(), state="MERGED")
        dispatched = []
        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "poll-state.json"
            with (
                mock.patch.object(sys, "argv", [
                    "poll_prs.py", "owner/repository#7", "--interval", "0.01",
                    "--state-file", str(state_path), "--on-change-command", "coordinator",
                ]),
                mock.patch.object(poll_prs, "validate_state_path", return_value=state_path),
                mock.patch.object(poll_prs, "query_pr", return_value=object()) as query_pr,
                mock.patch.object(poll_prs, "summary", side_effect=[terminal, terminal]),
                mock.patch.object(
                    poll_prs, "dispatch_event", side_effect=lambda _command, event: dispatched.append(event),
                ),
                mock.patch.object(poll_prs.time, "sleep"),
            ):
                self.assertEqual(poll_prs.main(), 0)

            saved = poll_prs.load_state(state_path)["prs"]["owner/repository#7"]

        self.assertEqual(query_pr.call_count, 2)
        self.assertEqual(
            [event["event"] for event in dispatched], ["changed", "review_completion_audit"]
        )
        self.assertTrue(saved["terminal"])

    def test_gh_json_sets_a_timeout(self) -> None:
        timeout = subprocess.TimeoutExpired(["gh", "api"], poll_prs.GH_TIMEOUT_SECONDS)
        with mock.patch.object(subprocess, "run", side_effect=timeout) as run:
            with self.assertRaisesRegex(RuntimeError, "timed out after"):
                poll_prs.gh_json(["api"])
        self.assertEqual(run.call_args.kwargs["timeout"], poll_prs.GH_TIMEOUT_SECONDS)


class PullRequestQueryTest(unittest.TestCase):
    def test_review_thread_queries_include_location_fields(self) -> None:
        fields = [
            "path", "line", "originalLine", "originalStartLine", "startLine", "diffSide", "startDiffSide",
        ]
        for query in [poll_prs.QUERY, poll_prs.REVIEW_THREADS_QUERY]:
            for field in fields:
                self.assertIn(field, query)
            self.assertIn("pullRequestReview { id }", query)
        self.assertIn("pullRequestReview { id }", poll_prs.THREAD_COMMENTS_QUERY)

    def test_fetches_every_connection_page(self) -> None:
        pr = {
            "reviews": connection([{"id": "review-1"}], True, "reviews-1"),
            "reviewThreads": connection(
                [{"id": "thread-1", "comments": connection([{"id": "thread-comment-1",
                    "pullRequestReview": {"id": "review-1"}}], True, "thread-1")}],
                True,
                "threads-1",
            ),
            "comments": connection([{"id": "comment-1"}], True, "comments-1"),
            "commits": {"nodes": [{"commit": {"statusCheckRollup": {"contexts": connection(
                [{"name": "check-1"}], True, "contexts-1"
            )}}}]},
        }

        def fake_gh_json(args, stdin=None):
            query = next(value.removeprefix("query=") for value in args if value.startswith("query="))
            if query == poll_prs.QUERY:
                return {"data": {"repository": {"pullRequest": pr}}}
            if query == poll_prs.REVIEWS_QUERY:
                return {"data": {"repository": {"pullRequest": {"reviews": connection([{"id": "review-2"}])}}}}
            if query == poll_prs.REVIEW_THREADS_QUERY:
                return {"data": {"repository": {"pullRequest": {"reviewThreads": connection([
                    {"id": "thread-2", "comments": connection([{"id": "thread-comment-3"}])}
                ])}}}}
            if query == poll_prs.COMMENTS_QUERY:
                return {"data": {"repository": {"pullRequest": {"comments": connection([{"id": "comment-2"}])}}}}
            if query == poll_prs.CHECK_CONTEXTS_QUERY:
                return {
                    "data": {"repository": {"pullRequest": {"commits": {"nodes": [{"commit": {
                        "statusCheckRollup": {"contexts": connection([{"name": "check-2"}])}
                    }}]}}}}
                }
            if query == poll_prs.THREAD_COMMENTS_QUERY:
                return {"data": {"node": {"comments": connection([{"id": "thread-comment-2",
                    "pullRequestReview": None}])}}}
            self.fail(f"unexpected query: {query}")

        with mock.patch.object(poll_prs, "gh_json", side_effect=fake_gh_json):
            result = poll_prs.query_pr("owner/repository", 7)

        self.assertEqual([item["id"] for item in result["reviews"]["nodes"]], ["review-1", "review-2"])
        self.assertEqual(
            [item["id"] for item in result["reviewThreads"]["nodes"]], ["thread-1", "thread-2"]
        )
        self.assertEqual(
            [item["id"] for item in result["reviewThreads"]["nodes"][0]["comments"]["nodes"]],
            ["thread-comment-1", "thread-comment-2"],
        )
        self.assertEqual(
            [item["review_id"] for item in result["reviewThreads"]["nodes"][0]["comments"]["nodes"]],
            ["review-1", None],
        )
        self.assertEqual([item["id"] for item in result["comments"]["nodes"]], ["comment-1", "comment-2"])
        self.assertEqual(
            [item["name"] for item in poll_prs.check_contexts(result)["nodes"]], ["check-1", "check-2"]
        )


class SummaryTest(unittest.TestCase):
    def test_detects_completed_codex_summary_for_current_head(self) -> None:
        value = completed_review_summary()
        self.assertEqual(poll_prs.codex_review_completion(value), {
            "comment_id": "summary-comment", "updated_at": "2026-08-30T17:10:33Z",
        })
        value["head_sha"] = "1234567890abcdef"
        self.assertIsNone(poll_prs.codex_review_completion(value))

    def test_completion_generation_changes_when_summary_is_updated(self) -> None:
        value = completed_review_summary()
        first = poll_prs.codex_review_completion(value)
        value["comments"][1]["updatedAt"] = "2026-08-30T17:20:00Z"
        self.assertNotEqual(poll_prs.codex_review_completion(value), first)

    def test_ignores_untrusted_exact_request_comments(self) -> None:
        value = completed_review_summary()
        expected = poll_prs.codex_review_completion(value)
        value["comments"].append({
            "author": {"login": "untrusted-contributor"},
            "body": "@codex review",
            "createdAt": "2026-08-30T18:00:00Z",
            "updatedAt": "2026-08-30T18:00:00Z",
        })
        self.assertEqual(poll_prs.codex_review_completion(value), expected)

    def test_rejects_completed_summary_from_untrusted_author(self) -> None:
        value = completed_review_summary()
        value["comments"][1]["author"] = {"login": "untrusted-contributor"}
        self.assertIsNone(poll_prs.codex_review_completion(value))

    def test_records_merge_state_and_classifies_pending_and_failed_checks(self) -> None:
        pr = {
            "url": "https://example.test/pr/1", "state": "OPEN", "title": "test", "headRefOid": "abc",
            "headRefName": "feature", "headRepository": {"nameWithOwner": "owner/repository"},
            "baseRefName": "main", "mergeable": "MERGEABLE", "mergeStateStatus": "BEHIND",
            "reviewDecision": None, "updatedAt": "2026-08-22T00:00:00Z",
            "reviewThreads": {"nodes": []}, "reviews": {"nodes": []}, "comments": {"nodes": []},
            "commits": {"nodes": [{"commit": {"statusCheckRollup": {"contexts": {"nodes": [
                {"__typename": "CheckRun", "name": "startup", "status": "COMPLETED", "conclusion": "STARTUP_FAILURE"},
                {"__typename": "CheckRun", "name": "stale", "status": "COMPLETED", "conclusion": "STALE"},
                {"__typename": "CheckRun", "name": "running", "status": "IN_PROGRESS", "conclusion": None},
                {"__typename": "StatusContext", "context": "pending", "state": "PENDING"},
                {"__typename": "StatusContext", "context": "expected", "state": "EXPECTED"},
                {"__typename": "StatusContext", "context": "done", "state": "SUCCESS"},
            ]}}}}]},
        }
        result = poll_prs.summary(pr)
        self.assertEqual(result["merge_state_status"], "BEHIND")
        changed_merge_state = dict(result)
        changed_merge_state["merge_state_status"] = "CLEAN"
        self.assertNotEqual(poll_prs.fingerprint(result), poll_prs.fingerprint(changed_merge_state))
        self.assertEqual([item.get("name") for item in result["failed_checks"]], ["startup", "stale"])
        self.assertEqual(
            [item.get("name", item.get("context")) for item in result["pending_checks"]],
            ["running", "pending", "expected"],
        )


if __name__ == "__main__":
    unittest.main()
