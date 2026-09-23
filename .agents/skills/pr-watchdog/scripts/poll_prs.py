#!/usr/bin/env python3
"""Poll GitHub PR metadata and emit only state changes as JSON Lines."""

import argparse
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


QUERY = """
query($owner: String!, $repo: String!, $number: Int!) {
  repository(owner: $owner, name: $repo) {
    pullRequest(number: $number) {
      url number state title updatedAt mergeable mergeStateStatus reviewDecision
      baseRefName headRefName headRefOid
      headRepository { nameWithOwner }
      reviews(first: 100) {
        nodes { id state body url author { login } commit { oid } }
        pageInfo { hasNextPage endCursor }
      }
      reviewThreads(first: 100) { nodes {
        id isResolved isOutdated path line originalLine originalStartLine startLine diffSide startDiffSide
        comments(first: 100) {
          nodes { id body url author { login } commit { oid } pullRequestReview { id } }
          pageInfo { hasNextPage endCursor }
        }
      } pageInfo { hasNextPage endCursor } }
      comments(first: 100) {
        nodes { id body url author { login } createdAt updatedAt }
        pageInfo { hasNextPage endCursor }
      }
      commits(last: 1) { nodes { commit { statusCheckRollup { contexts(first: 100) { nodes {
        __typename
        ... on CheckRun { name status conclusion detailsUrl }
        ... on StatusContext { context state targetUrl }
      } pageInfo { hasNextPage endCursor } } } } } }
    }
  }
}
"""


REVIEWS_QUERY = """
query($owner: String!, $repo: String!, $number: Int!, $after: String!) {
  repository(owner: $owner, name: $repo) {
    pullRequest(number: $number) {
      reviews(first: 100, after: $after) {
        nodes { id state body url author { login } commit { oid } }
        pageInfo { hasNextPage endCursor }
      }
    }
  }
}
"""

REVIEW_THREADS_QUERY = """
query($owner: String!, $repo: String!, $number: Int!, $after: String!) {
  repository(owner: $owner, name: $repo) {
    pullRequest(number: $number) {
      reviewThreads(first: 100, after: $after) { nodes {
        id isResolved isOutdated path line originalLine originalStartLine startLine diffSide startDiffSide
        comments(first: 100) {
          nodes { id body url author { login } commit { oid } pullRequestReview { id } }
          pageInfo { hasNextPage endCursor }
        }
      } pageInfo { hasNextPage endCursor } }
    }
  }
}
"""

COMMENTS_QUERY = """
query($owner: String!, $repo: String!, $number: Int!, $after: String!) {
  repository(owner: $owner, name: $repo) {
    pullRequest(number: $number) {
      comments(first: 100, after: $after) {
        nodes { id body url author { login } createdAt updatedAt }
        pageInfo { hasNextPage endCursor }
      }
    }
  }
}
"""

CHECK_CONTEXTS_QUERY = """
query($owner: String!, $repo: String!, $number: Int!, $after: String!) {
  repository(owner: $owner, name: $repo) {
    pullRequest(number: $number) {
      commits(last: 1) { nodes { commit { statusCheckRollup { contexts(first: 100, after: $after) {
        nodes {
          __typename
          ... on CheckRun { name status conclusion detailsUrl }
          ... on StatusContext { context state targetUrl }
        }
        pageInfo { hasNextPage endCursor }
      } } } } }
    }
  }
}
"""

THREAD_COMMENTS_QUERY = """
query($id: ID!, $after: String!) {
  node(id: $id) {
    ... on PullRequestReviewThread {
      comments(first: 100, after: $after) {
        nodes { id body url author { login } commit { oid } pullRequestReview { id } }
        pageInfo { hasNextPage endCursor }
      }
    }
  }
}
"""

GH_TIMEOUT_SECONDS = 30
DISPATCH_TIMEOUT_SECONDS = 15
CODEX_REVIEW_SUMMARY_MARKER = "<!-- codex-pull-request-review-summary -->"
CODEX_REVIEW_AUTHORS = frozenset({"chatgpt-codex-connector", "chatgpt-codex-connector[bot]"})


def gh_json(args: list[str], stdin: str | None = None) -> Any:
    try:
        result = subprocess.run(
            ["gh", *args], input=stdin, text=True, capture_output=True, check=False,
            timeout=GH_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"gh command timed out after {GH_TIMEOUT_SECONDS} seconds") from error
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "gh command failed")
    return json.loads(result.stdout)


def current_repo() -> str:
    return gh_json(["repo", "view", "--json", "nameWithOwner"])["nameWithOwner"]


def canonicalize(value: str, default_repo: str | None) -> tuple[str, int]:
    match = re.fullmatch(r"https://github\.com/([^/]+)/([^/]+)/pull/(\d+)/?", value)
    if match:
        return f"{match.group(1)}/{match.group(2)}", int(match.group(3))
    match = re.fullmatch(r"([^/]+)/([^#]+)#(\d+)", value)
    if match:
        return f"{match.group(1)}/{match.group(2)}", int(match.group(3))
    if value.isdigit() and default_repo:
        return default_repo, int(value)
    raise ValueError(f"unsupported PR identifier: {value}")


def paginate_pr_connection(
    repo: str, number: int, connection: dict[str, Any], query: str, field: str
) -> list[dict[str, Any]]:
    nodes = connection["nodes"]
    page = connection
    owner, name = repo.split("/", 1)
    while page["pageInfo"]["hasNextPage"]:
        raw = gh_json(
            [
                "api", "graphql", "-f", f"query={query}", "-F", f"owner={owner}",
                "-F", f"repo={name}", "-F", f"number={number}",
                "-f", f"after={page['pageInfo']['endCursor']}",
            ]
        )
        page = raw["data"]["repository"]["pullRequest"][field]
        nodes.extend(page["nodes"])
    return nodes


def paginate_thread_comments(thread: dict[str, Any]) -> None:
    connection = thread["comments"]
    nodes = connection["nodes"]
    page = connection
    while page["pageInfo"]["hasNextPage"]:
        raw = gh_json(
            [
                "api", "graphql", "-f", f"query={THREAD_COMMENTS_QUERY}",
                "-F", f"id={thread['id']}", "-f", f"after={page['pageInfo']['endCursor']}",
            ]
        )
        page = raw["data"]["node"]["comments"]
        nodes.extend(page["nodes"])


def normalize_review_comment(comment: dict[str, Any]) -> None:
    """Expose the owning review while preserving comments with no association."""
    review = comment.get("pullRequestReview")
    comment["review_id"] = review.get("id") if isinstance(review, dict) else None


def paginate_check_contexts(repo: str, number: int, connection: dict[str, Any]) -> list[dict[str, Any]]:
    nodes = connection["nodes"]
    page = connection
    owner, name = repo.split("/", 1)
    while page["pageInfo"]["hasNextPage"]:
        raw = gh_json(
            [
                "api", "graphql", "-f", f"query={CHECK_CONTEXTS_QUERY}",
                "-F", f"owner={owner}", "-F", f"repo={name}", "-F", f"number={number}",
                "-f", f"after={page['pageInfo']['endCursor']}",
            ]
        )
        next_pr = raw["data"]["repository"]["pullRequest"]
        page = check_contexts(next_pr)
        if page is None:
            raise RuntimeError("status check rollup disappeared while fetching pages")
        nodes.extend(page["nodes"])
    return nodes


def check_contexts(pr: dict[str, Any]) -> dict[str, Any] | None:
    commits = pr["commits"]["nodes"]
    if not commits:
        return None
    rollup = commits[0]["commit"].get("statusCheckRollup")
    return rollup.get("contexts") if rollup else None


def query_pr(repo: str, number: int) -> dict[str, Any]:
    owner, name = repo.split("/", 1)
    raw = gh_json(
        [
            "api", "graphql", "-f", f"query={QUERY}", "-F", f"owner={owner}",
            "-F", f"repo={name}", "-F", f"number={number}",
        ]
    )
    pr = raw["data"]["repository"]["pullRequest"]
    if pr is None:
        raise RuntimeError(f"PR not found: {repo}#{number}")
    pr["reviews"]["nodes"] = paginate_pr_connection(
        repo, number, pr["reviews"], REVIEWS_QUERY, "reviews"
    )
    pr["reviewThreads"]["nodes"] = paginate_pr_connection(
        repo, number, pr["reviewThreads"], REVIEW_THREADS_QUERY, "reviewThreads"
    )
    pr["comments"]["nodes"] = paginate_pr_connection(
        repo, number, pr["comments"], COMMENTS_QUERY, "comments"
    )
    contexts = check_contexts(pr)
    if contexts is not None:
        contexts["nodes"] = paginate_check_contexts(repo, number, contexts)
    for thread in pr["reviewThreads"]["nodes"]:
        paginate_thread_comments(thread)
        for comment in thread["comments"]["nodes"]:
            normalize_review_comment(comment)
    return pr


def summary(pr: dict[str, Any]) -> dict[str, Any]:
    threads = pr["reviewThreads"]["nodes"]
    contexts = []
    rollup_contexts = check_contexts(pr)
    if rollup_contexts is not None:
        contexts = rollup_contexts["nodes"]
    failed = [
        item for item in contexts
        if item.get("conclusion") in {
            "FAILURE", "TIMED_OUT", "CANCELLED", "ACTION_REQUIRED", "STARTUP_FAILURE", "STALE",
        }
        or item.get("state") in {"FAILURE", "ERROR"}
    ]
    unresolved = [thread for thread in threads if not thread["isResolved"]]
    return {
        "url": pr["url"], "state": pr["state"], "title": pr["title"],
        "head_sha": pr["headRefOid"], "head_branch": pr["headRefName"],
        "head_repository": (pr["headRepository"] or {}).get("nameWithOwner"),
        "base_branch": pr["baseRefName"], "mergeable": pr["mergeable"],
        "merge_state_status": pr["mergeStateStatus"],
        "review_decision": pr["reviewDecision"], "updated_at": pr["updatedAt"],
        "unresolved_threads": unresolved, "reviews": pr["reviews"]["nodes"],
        "comments": pr["comments"]["nodes"], "failed_checks": failed,
        "pending_checks": [
            item for item in contexts
            if item.get("status") not in {"COMPLETED", None}
            or item.get("state") in {"PENDING", "EXPECTED"}
        ],
    }


def fingerprint(value: dict[str, Any]) -> str:
    # updated_at is deliberately excluded: it changes even for irrelevant metadata churn.
    stable = {key: item for key, item in value.items() if key != "updated_at"}
    return hashlib.sha256(json.dumps(stable, sort_keys=True).encode()).hexdigest()


def codex_review_completion(value: dict[str, Any]) -> dict[str, str] | None:
    """Return the trusted current-head Codex completion generation, if any."""
    head_sha = value.get("head_sha")
    if not head_sha:
        return None
    commit_marker = f"`{head_sha[:7]}`"
    for comment in value.get("comments", []):
        body = comment.get("body") or ""
        author = (comment.get("author") or {}).get("login")
        updated_at = comment.get("updatedAt")
        if (
            comment.get("id")
            and updated_at
            and author in CODEX_REVIEW_AUTHORS
            and CODEX_REVIEW_SUMMARY_MARKER in body
            and "**Completed**" in body
            and commit_marker in body
        ):
            return {"comment_id": comment["id"], "updated_at": updated_at}
    return None


def known_worktree_paths() -> list[Path]:
    """Return every worktree registered by the checkout running the poller."""
    result = subprocess.run(
        ["git", "worktree", "list", "--porcelain"], text=True, capture_output=True, check=False
    )
    if result.returncode:
        message = result.stderr.strip() or "git worktree list failed"
        raise RuntimeError(f"cannot verify state-file location: {message}")
    return [
        Path(line.removeprefix("worktree ")).resolve()
        for line in result.stdout.splitlines()
        if line.startswith("worktree ")
    ]


def validate_state_path(path: Path, worktrees: list[Path] | None = None) -> Path:
    """Reject state stored in this checkout or any worktree known to Git."""
    resolved_path = path.resolve()
    roots = worktrees if worktrees is not None else known_worktree_paths()
    for root in roots:
        resolved_root = root.resolve()
        if resolved_path == resolved_root or resolved_root in resolved_path.parents:
            raise ValueError(f"state file must be outside git worktrees: {resolved_path}")
    return resolved_path


def load_state(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        return {"prs": {}}
    except json.JSONDecodeError as error:
        raise RuntimeError(f"invalid state file {path}: {error}") from error


def save_state(path: Path, state: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")
    os.replace(temporary, path)


def dispatch_event(command: str, event: dict[str, Any]) -> None:
    """Invoke the configured coordinator hook with one JSON event on stdin.

    The poller remains responsible only for GitHub metadata; the hook is the
    durable hand-off to a coordinator (for example, a Codex session queue).
    A short timeout prevents a broken hook from stopping monitoring.
    """
    argv = shlex.split(command)
    if not argv:
        raise RuntimeError("dispatch command is empty")
    try:
        result = subprocess.run(
            argv,
            input=json.dumps(event, ensure_ascii=False) + "\n",
            text=True,
            capture_output=True,
            check=False,
            timeout=DISPATCH_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError(f"dispatch command failed: {error}") from error
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip() or "non-zero exit"
        raise RuntimeError(f"dispatch command exited {result.returncode}: {detail}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("prs", nargs="+", help="PR number, owner/repo#number, or GitHub PR URL")
    parser.add_argument("--interval", type=float, default=60, help="seconds between polls (default: 60)")
    parser.add_argument("--once", action="store_true", help="poll once and exit")
    parser.add_argument("--state-file", type=Path, help="durable state file outside worktrees")
    parser.add_argument(
        "--on-change-command",
        help="run this command with each changed JSON event on stdin (use a fast coordinator enqueue command)",
    )
    args = parser.parse_args()
    if args.interval <= 0:
        parser.error("--interval must be positive")
    default_repo = current_repo() if any(value.isdigit() for value in args.prs) else None
    targets = [canonicalize(value, default_repo) for value in args.prs]
    if len(set(targets)) != len(targets):
        parser.error("duplicate PR identifiers")
    state_path = args.state_file or Path.home() / ".local/state/pr-watchdog/poll-state.json"
    try:
        state_path = validate_state_path(state_path)
    except (RuntimeError, ValueError) as error:
        parser.error(str(error))
    state = load_state(state_path)
    active_targets = [
        (repo, number)
        for repo, number in targets
        if not state["prs"].get(f"{repo}#{number}", {}).get("terminal")
    ]
    if not active_targets:
        return 0
    poll_errors = False
    while active_targets:
        next_targets = []
        for repo, number in active_targets:
            key = f"{repo}#{number}"
            try:
                value = summary(query_pr(repo, number))
                digest = fingerprint(value)
                previous = state["prs"].get(key, {})
                audit = previous.get("review_completion_audit")
                completion = codex_review_completion(value)
                head_sha = value.get("head_sha")
                if (
                    not isinstance(audit, dict)
                    or audit.get("head_sha") != head_sha
                    or not completion
                    or audit.get("summary_comment_id") != completion["comment_id"]
                    or audit.get("summary_updated_at") != completion["updated_at"]
                ):
                    audit = None
                audit_scheduled = False
                if completion and audit is None:
                    audit = {
                        "head_sha": head_sha,
                        "summary_comment_id": completion["comment_id"],
                        "summary_updated_at": completion["updated_at"],
                        "pending": True,
                        "observed_at": time.time(),
                    }
                    audit_scheduled = True
                change_dispatch_succeeded = True
                if previous.get("fingerprint") != digest:
                    event = {"event": "changed", "pr": key, "data": value}
                    print(json.dumps(event, ensure_ascii=False), flush=True)
                    if args.on_change_command:
                        try:
                            dispatch_event(args.on_change_command, event)
                        except RuntimeError as error:
                            poll_errors = True
                            print(json.dumps({
                                "event": "dispatch_error", "pr": key, "error": str(error),
                            }, ensure_ascii=False), flush=True)
                            change_dispatch_succeeded = False
                audit_dispatch_succeeded = True
                if audit and audit.get("pending") and not audit_scheduled:
                    event = {
                        "event": "review_completion_audit",
                        "pr": key,
                        "head_sha": head_sha,
                        "summary_comment_id": audit["summary_comment_id"],
                        "summary_updated_at": audit["summary_updated_at"],
                        "data": value,
                    }
                    print(json.dumps(event, ensure_ascii=False), flush=True)
                    if args.on_change_command:
                        try:
                            dispatch_event(args.on_change_command, event)
                        except RuntimeError as error:
                            poll_errors = True
                            print(json.dumps({
                                "event": "dispatch_error", "pr": key, "error": str(error),
                            }, ensure_ascii=False), flush=True)
                            audit_dispatch_succeeded = False
                    if audit_dispatch_succeeded:
                        audit["pending"] = False
                        audit["dispatched_at"] = time.time()
                # Do not retire a terminal PR until its final transition has
                # reached the coordinator; otherwise a transient hook failure
                # would lose the only event that ends the watch.
                terminal = (
                    value["state"] in {"CLOSED", "MERGED"}
                    and change_dispatch_succeeded
                    and audit_dispatch_succeeded
                    and not (audit and audit.get("pending"))
                )
                if terminal:
                    audit = None
                state["prs"][key] = {
                    # Keep the old fingerprint after a failed hand-off so the
                    # next cycle retries the coordinator trigger.
                    "fingerprint": (
                        digest if change_dispatch_succeeded else previous.get("fingerprint")
                    ),
                    "last_polled_at": time.time(),
                    "terminal": terminal,
                    "terminal_state": value["state"] if terminal else None,
                    "review_completion_audit": audit,
                }
                if not terminal:
                    next_targets.append((repo, number))
            except Exception as error:  # Keep other PRs alive if one becomes inaccessible.
                poll_errors = True
                print(json.dumps({"event": "poll_error", "pr": key, "error": str(error)}, ensure_ascii=False), flush=True)
                next_targets.append((repo, number))
        save_state(state_path, state)
        if args.once:
            return 1 if poll_errors else 0
        active_targets = next_targets
        if not active_targets:
            return 0
        time.sleep(args.interval)


if __name__ == "__main__":
    sys.exit(main())
