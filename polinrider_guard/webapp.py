"""Local web frontend for polinrider-guard.

Either paste a git URL (optionally with a token, for private repos) and it
gets cloned into a scratch directory, or point it at a path already on disk
(e.g. a repo you've already cloned, or one mounted into this project's
Docker image at /scan). Either way it's run through the same scanner steps
as the CLI's run_guard(), with progress streamed back to the browser as it
goes. See README.md's "Web UI" section.

URL clones are full clones, not shallow (--depth 1) ones: the scan's clone
directory is kept around after scanning (see _last_scan_clone below) so
Recovery and the file viewer can reuse it afterward, and both of those need
complete history/content to work correctly -- a shallow clone would make
Recovery silently blind to anything outside the tip commit.

Never binds to a public interface by default. Several distinct exposure
risks if you do: the "server clones whatever URL you give it" behavior is
SSRF-shaped, local-path scanning and the file viewer reflect file contents
back to whoever can reach the port, and a scanned repo's clone persists on
the server's disk until the next URL scan replaces it -- all only
acceptable on localhost, or behind your own auth, if you ever pass a
non-loopback --host.
"""
from __future__ import annotations

import json as jsonlib
import os
import re
import shutil
import stat
import subprocess
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Generator, Iterator
from urllib.parse import quote, urlsplit, urlunsplit

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel

from . import (
    guard,
    recovery,
    scan_clock_tamper,
    scan_commit_camouflage,
    scan_ioc,
    scan_masquerade,
    scan_padding,
    scan_vscode,
)
from .guard import SCANNER_STEPS, build_report
from .skip_lists import SKIP_DIR_NAMES

# Recovery (history rewrite / force-push) is the one operation in this whole
# app that can destroy a collaborator's clone if triggered by accident, so
# it's gated behind exact typed confirmation phrases -- checked server-side,
# not just disabled buttons client-side, since the browser can't be trusted
# to enforce this on its own.
CONFIRM_APPLY_PHRASE = "REWRITE HISTORY"
CONFIRM_PUSH_PHRASE = "FORCE PUSH"
CONFIRM_REMOVE_TASK_PHRASE = "REMOVE TASK"

STATIC_DIR = Path(__file__).parent / "web_static"
CLONE_TIMEOUT_SECONDS = 300  # full clones take longer than the old --depth 1 ones

# The most recent URL-sourced scan's clone directory. Kept alive after
# scanning finishes (unlike the old "clone, scan, delete" flow) so Recovery
# and the file viewer have something to work with -- this is a local,
# single-user tool, so "keep exactly one such clone around, replacing it
# when the next URL scan starts" is a deliberately simple cleanup policy
# rather than a TTL/multi-tenant cache. Local-path scans need no entry here
# since the directory they point at already persists on its own.
_last_scan_clone: Path | None = None
_last_scan_clone_lock = threading.Lock()

# Git-dependent scanners get their own handling in _run_one_scanner (need a
# NotAGitRepoError catch each), so they're excluded from this plain map.
_SCAN_FUNCS = {
    "extension_masquerade": scan_masquerade.scan_path,
    "vscode_tasks": scan_vscode.scan_path,
    "hidden_payload_padding": scan_padding.scan_path,
    "clock_tamper_tooling": scan_clock_tamper.scan_path,
    "ioc_literal_match": scan_ioc.scan_path,
}


def _run_one_scanner(key: str, root: Path) -> tuple[str, list[dict], str | None]:
    """Run a single scanner, returning (step key, findings-as-dicts,
    git_skipped_reason). Runs in a worker thread -- see _run_scan.
    """
    if key == "commit_camouflage":
        try:
            return key, [f.to_dict() for f in scan_commit_camouflage.scan_path(root)], None
        except scan_commit_camouflage.NotAGitRepoError:
            return key, [], "not a git repository"
    return key, [f.to_dict() for f in _SCAN_FUNCS[key](root)], None

# Remote git URLs only (http/https/git/ssh, or scp-style git@host:path).
# Deliberately rejects bare filesystem paths and file:// here -- that's what
# the separate `path` field is for, with its own explicit handling below.
_ALLOWED_URL_RE = re.compile(r"^(https?://|git://|ssh://|git@[\w.-]+:)", re.IGNORECASE)

_AUTH_ERROR_MARKERS = (
    "authentication failed",
    "could not read username",
    "could not read password",
    "permission denied",
    "403",
    "401",
    "repository not found",
    "invalid username or password",
    "invalid username or token",
)

app = FastAPI(title="polinrider-guard")


class ScanRequest(BaseModel):
    url: str | None = None
    ref: str | None = None
    path: str | None = None
    token: str | None = None


def _validate_request(req: ScanRequest) -> None:
    has_url = bool(req.url and req.url.strip())
    has_path = bool(req.path and req.path.strip())

    if has_url and has_path:
        raise HTTPException(400, "provide either a git url or a local path, not both")
    if not has_url and not has_path:
        raise HTTPException(400, "url or path is required")

    if has_url:
        url = req.url.strip()
        if not _ALLOWED_URL_RE.match(url):
            raise HTTPException(
                400,
                "url must be a remote git URL (http(s)://, git://, ssh://, or "
                "git@host:path) -- use the local path field for a repo already on disk",
            )
        if req.token and urlsplit(url).scheme.lower() not in ("http", "https"):
            raise HTTPException(400, "token auth is only supported for http(s) git URLs")
    else:
        p = Path(req.path.strip())
        if not p.exists():
            raise HTTPException(400, f"path does not exist: {p}")
        if not p.is_dir():
            raise HTTPException(400, f"path is not a directory: {p}")


def _inject_token(url: str, token: str) -> str:
    """Embed a token (or "username:token") into a URL as HTTP basic-auth
    userinfo, e.g. https://TOKEN@github.com/owner/repo.git. Covers GitHub
    PATs (plain token as username) and providers that want a specific
    username, like GitLab's oauth2:TOKEN or Bitbucket's user:app-password.
    """
    user, _, pw = token.partition(":")
    userinfo = quote(user, safe="")
    if pw:
        userinfo += ":" + quote(pw, safe="")
    parts = urlsplit(url)
    netloc = f"{userinfo}@{parts.hostname}"
    if parts.port:
        netloc += f":{parts.port}"
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


def _looks_like_auth_error(stderr: str) -> bool:
    low = stderr.lower()
    return any(marker in low for marker in _AUTH_ERROR_MARKERS)


def _rmtree_force(path: Path) -> None:
    def _on_error(func, p, exc_info):
        os.chmod(p, stat.S_IWRITE)
        func(p)

    shutil.rmtree(path, onerror=_on_error)


# Batch-scan: point the local-path field at a parent folder (e.g. a
# workspace directory with many repos cloned inside it) instead of a
# single repo, and scan every git repo found under it in one pass.
MAX_BATCH_REPOS = 200  # sane bound on a dashboard row count / SSE payload size
MAX_BATCH_DIRS_VISITED = 20_000  # safety net against walking a huge non-repo tree
# How many repos to scan concurrently. Deliberately bounded, not unbounded:
# each repo's own scan already spins up len(SCANNER_STEPS) worker threads
# internally, so this multiplies thread count by however many repos are in
# flight at once -- at the default of 8, worst case is 8 * 6 = 48 threads.
# A module-level variable (not a constant) so main() below can override it
# from --batch-workers before the server starts; nothing else should change
# it at runtime.
BATCH_SCAN_MAX_WORKERS = 8


def _iter_git_repos(root: Path) -> Iterator[Path]:
    """Yield every directory at or under `root` that is a git repository
    (has a .git file or directory). Once a directory is identified as a
    repo, its own subdirectories are not walked further -- a submodule
    stays bundled with its parent repo's scan rather than becoming a
    separate top-level target. Prunes the same directory names the
    scanners themselves skip (node_modules, vendor, build output, caches),
    plus a hard cap on total directories visited, so this can't get stuck
    walking a huge tree that isn't actually full of separate repos.
    """
    visited = 0

    def _walk(d: Path) -> Iterator[Path]:
        nonlocal visited
        if (d / ".git").exists():
            yield d
            return
        try:
            children = sorted(p for p in d.iterdir() if p.is_dir())
        except (OSError, PermissionError):
            return
        for child in children:
            if child.name in SKIP_DIR_NAMES:
                continue
            visited += 1
            if visited > MAX_BATCH_DIRS_VISITED:
                return
            yield from _walk(child)

    yield from _walk(root)


class BatchScanRequest(BaseModel):
    path: str


def _validate_batch_scan_path(path: str) -> Path:
    p = Path(path.strip())
    if not p.exists():
        raise HTTPException(400, f"path does not exist: {p}")
    if not p.is_dir():
        raise HTTPException(400, f"path is not a directory: {p}")
    return p.resolve()


def _run_batch_scan(root: Path) -> Generator[tuple[str, dict], None, None]:
    """Discover every git repo under `root`, then scan each one with the
    same run_guard() pipeline the CLI and single-repo web scan use,
    streaming progress as each repo finishes.

    Repos are scanned with bounded concurrency (BATCH_SCAN_MAX_WORKERS)
    rather than unbounded, since each repo's own scan already runs its six
    scanners concurrently internally -- see BATCH_SCAN_MAX_WORKERS above.
    """
    yield ("progress", {"step": "discover", "label": f"Discovering git repositories under {root}..."})

    discovered: list[Path] = []
    truncated = False
    for repo in _iter_git_repos(root):
        if len(discovered) >= MAX_BATCH_REPOS:
            truncated = True
            break
        discovered.append(repo)

    if not discovered:
        yield ("progress", {"step": "discover", "label": "No git repositories found", "done": True})
        yield ("done", {"root": str(root), "repos": [], "total_repos": 0, "dirty_repos": 0, "total_findings": 0, "truncated": False})
        return

    repo_list = [
        {"path": str(p), "name": str(p.relative_to(root)) if p != root else p.name or str(p)}
        for p in discovered
    ]
    discover_label = f"Found {len(discovered)} repositor{'y' if len(discovered) == 1 else 'ies'}"
    if truncated:
        discover_label += f" (showing first {MAX_BATCH_REPOS})"
    yield (
        "progress",
        {"step": "discover", "label": discover_label, "done": True, "repos": repo_list, "truncated": truncated},
    )

    reports: list[dict] = []
    with ThreadPoolExecutor(max_workers=BATCH_SCAN_MAX_WORKERS) as executor:
        futures = {executor.submit(guard.run_guard, p, include_git=True): p for p in discovered}
        for future in as_completed(futures):
            repo_path = futures[future]
            try:
                report = future.result()
            except Exception as exc:
                yield (
                    "progress",
                    {
                        "step": "repo",
                        "repo_path": str(repo_path),
                        "label": f"{repo_path.name}: scan failed ({exc})",
                        "done": True,
                        "error": True,
                    },
                )
                continue
            report["source_path"] = str(repo_path)
            reports.append(report)
            total = report["summary"]["total_findings"]
            yield (
                "progress",
                {
                    "step": "repo",
                    "repo_path": str(repo_path),
                    "label": f"{repo_path.name}: {total} finding(s)",
                    "done": True,
                    "findings_count": total,
                    "by_severity": report["summary"]["by_severity"],
                },
            )

    reports.sort(key=lambda r: r["source_path"])
    total_findings = sum(r["summary"]["total_findings"] for r in reports)
    dirty_repos = sum(1 for r in reports if r["summary"]["total_findings"] > 0)
    yield (
        "done",
        {
            "root": str(root),
            "repos": reports,
            "total_repos": len(reports),
            "dirty_repos": dirty_repos,
            "total_findings": total_findings,
            "truncated": truncated,
        },
    )


@app.post("/api/batch-scan")
def batch_scan(req: BatchScanRequest) -> JSONResponse:
    root = _validate_batch_scan_path(req.path)

    result = None
    for event, data in _run_batch_scan(root):
        if event == "done":
            result = data
    return JSONResponse(result)


@app.post("/api/batch-scan/stream")
def batch_scan_stream(req: BatchScanRequest) -> StreamingResponse:
    root = _validate_batch_scan_path(req.path)

    def generate():
        for event, data in _run_batch_scan(root):
            yield _sse(event, data)

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


def _run_scan(
    url: str | None, ref: str | None, path: str | None, token: str | None
) -> Generator[tuple[str, dict], None, None]:
    """Do the clone-or-locate + scan work, yielding (event, data) pairs:
    any number of "progress" events, then exactly one "done" (with the
    report) or "error" event.

    Used by both /api/scan (JSON) and /api/scan/stream (SSE) so the two
    endpoints can't drift -- the JSON one just drains this generator and
    keeps the last done/error instead of re-implementing the scan.
    """
    global _last_scan_clone

    if path:
        root = Path(path).resolve()
        yield ("progress", {"step": "clone", "label": f"Using local path {root}", "done": True})
    else:
        with _last_scan_clone_lock:
            if _last_scan_clone is not None and _last_scan_clone.exists():
                _rmtree_force(_last_scan_clone)
            _last_scan_clone = None

        tmpdir = Path(tempfile.mkdtemp(prefix="polinrider-guard-web-"))
        root = tmpdir

        yield ("progress", {"step": "clone", "label": f"Cloning {url}..."})

        clone_url = _inject_token(url, token) if token else url
        cmd = ["git", "clone"]
        if ref:
            cmd += ["--branch", ref]
        cmd += [clone_url, str(tmpdir)]

        env = os.environ.copy()
        env["GIT_TERMINAL_PROMPT"] = "0"

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=CLONE_TIMEOUT_SECONDS, env=env
            )
        except subprocess.TimeoutExpired:
            yield ("error", {"message": "git clone timed out"})
            _rmtree_force(tmpdir)
            return

        if result.returncode != 0:
            stderr = result.stderr.strip()[-2000:]
            if token:
                stderr = stderr.replace(clone_url, url).replace(token, "***")
            message = f"git clone failed: {stderr}"
            if _looks_like_auth_error(stderr) and not token:
                message += (
                    " -- this looks like an authentication error. If it's a private "
                    "repository, provide a personal access token."
                )
            elif _looks_like_auth_error(stderr):
                message += " -- the token was rejected; check it has repo read access."
            yield ("error", {"message": message})
            _rmtree_force(tmpdir)
            return

        yield ("progress", {"step": "clone", "label": "Clone complete", "done": True})

        # Kept alive from here on (not cleaned up in a finally below) so
        # Recovery and the file viewer can reuse it after this scan
        # finishes; replaced on the next URL scan, not before.
        with _last_scan_clone_lock:
            _last_scan_clone = tmpdir

    scanners: dict[str, list[dict]] = {}
    labels = dict(SCANNER_STEPS)
    git_skipped_reason = None

    # All scanners walk the same read-only tree independently (the two
    # git-dependent ones just also shell out to `git log`), so there's
    # nothing shared/mutable to race on -- run them concurrently and
    # stream each one's "done" event the moment it actually finishes,
    # in whichever order that turns out to be, rather than the fixed
    # SCANNER_STEPS order a sequential run would force.
    for key, label in SCANNER_STEPS:
        yield ("progress", {"step": key, "label": f"Running {label}..."})

    with ThreadPoolExecutor(max_workers=len(SCANNER_STEPS)) as executor:
        futures = {executor.submit(_run_one_scanner, key, root): key for key, _ in SCANNER_STEPS}
        for future in as_completed(futures):
            key, findings, skip_reason = future.result()
            scanners[key] = findings
            if skip_reason:
                git_skipped_reason = skip_reason
            label = labels[key]
            yield (
                "progress",
                {
                    "step": key,
                    "label": f"{label}: {len(findings)} finding(s)",
                    "done": True,
                    "count": len(findings),
                },
            )

    report = build_report(root, scanners, git_skipped_reason)
    if url:
        report["source_url"] = url
    report["source_path"] = str(root)
    yield ("done", report)


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {jsonlib.dumps(data)}\n\n"


@app.post("/api/scan")
def scan(req: ScanRequest) -> JSONResponse:
    _validate_request(req)

    report = None
    error_message = None
    for event, data in _run_scan(req.url, req.ref, req.path, req.token):
        if event == "done":
            report = data
        elif event == "error":
            error_message = data["message"]

    if error_message:
        raise HTTPException(400, error_message)
    return JSONResponse(report)


@app.post("/api/scan/stream")
def scan_stream(req: ScanRequest) -> StreamingResponse:
    _validate_request(req)

    def generate():
        for event, data in _run_scan(req.url, req.ref, req.path, req.token):
            yield _sse(event, data)

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


class RecoveryAnalyzeRequest(BaseModel):
    path: str


class RecoveryApplyRequest(BaseModel):
    path: str
    confirm: str
    push: bool = False
    push_confirm: str | None = None
    token: str | None = None


class RecoveryRemoveTasksRequest(BaseModel):
    path: str
    confirm: str


def _validate_recovery_path(path: str) -> Path:
    p = Path(path.strip())
    if not p.exists():
        raise HTTPException(400, f"path does not exist: {p}")
    if not p.is_dir():
        raise HTTPException(400, f"path is not a directory: {p}")
    result = subprocess.run(
        ["git", "-C", str(p), "rev-parse", "--is-inside-work-tree"],
        capture_output=True, text=True,
    )
    if result.returncode != 0 or result.stdout.strip() != "true":
        raise HTTPException(400, f"{p} is not a git repository")
    return p.resolve()


def _validate_recover_apply_request(req: RecoveryApplyRequest) -> Path:
    root = _validate_recovery_path(req.path)
    if req.confirm != CONFIRM_APPLY_PHRASE:
        raise HTTPException(400, f'confirm must be exactly "{CONFIRM_APPLY_PHRASE}"')
    if req.push and req.push_confirm != CONFIRM_PUSH_PHRASE:
        raise HTTPException(400, f'push_confirm must be exactly "{CONFIRM_PUSH_PHRASE}" to also push')
    return root


def _validate_recover_remove_tasks_request(req: RecoveryRemoveTasksRequest) -> Path:
    root = _validate_recovery_path(req.path)
    if req.confirm != CONFIRM_REMOVE_TASK_PHRASE:
        raise HTTPException(400, f'confirm must be exactly "{CONFIRM_REMOVE_TASK_PHRASE}"')
    return root


def _get_origin_url(path: Path) -> str | None:
    result = subprocess.run(
        ["git", "-C", str(path), "remote", "get-url", "origin"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None


_RECOVER_ANALYZE_LABELS = {
    "blobs": "Checking IOC / padding-hidden lines and whole clock-tamper script files...",
    "masquerade": "Checking font/image-masquerade blob signatures across history...",
    "camouflage": "Checking for camouflage commits...",
    "vscode": "Checking risky VS Code task configuration...",
    "vscode_history": "Checking historical tasks.json blobs across history...",
}


def _run_recover_analyze(root: Path) -> Generator[tuple[str, dict], None, None]:
    """Read-only: report what a rewrite would strip/blank, without touching
    anything. Covers all six of recovery.py's signals -- IOC/padding lines
    (stripped), whole clock-tamper script blobs (blanked), confirmed
    extension-masquerade blobs (blanked), historical risky-tasks.json blobs
    (blanked), camouflage commits, and risky VS Code tasks in the current
    tree (the last two reported only -- see recovery.py's module docstring
    for why those two aren't auto-rewritten).

    Five genuinely independent git/filesystem operations, run concurrently.
    Streams each one's "done" the moment it actually finishes, same pattern
    as the main scan.
    """
    patterns = recovery.load_patterns()

    for key, label in _RECOVER_ANALYZE_LABELS.items():
        yield ("progress", {"step": key, "label": label})

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {
            executor.submit(recovery.analyze_blobs, root, patterns): "blobs",
            executor.submit(recovery.find_masquerade_blobs, root): "masquerade",
            executor.submit(recovery.find_camouflage_commits, root): "camouflage",
            executor.submit(recovery.find_risky_vscode_tasks, root): "vscode",
            executor.submit(recovery.find_risky_vscode_task_blobs, root): "vscode_history",
        }
        blob_result = None
        masquerade_blobs = None
        camouflage_commits = None
        vscode_findings = None
        vscode_task_blobs = None
        for future in as_completed(futures):
            key = futures[future]
            if key == "blobs":
                blob_result = future.result()
                line_findings, clock_tamper_blobs = blob_result
                blobs_affected_n = len({sha for sha, _, _ in line_findings})
                yield (
                    "progress",
                    {
                        "step": "blobs",
                        "label": (
                            f"Found {len(line_findings)} matching line(s) across {blobs_affected_n} blob(s), "
                            f"plus {len(clock_tamper_blobs)} whole clock-tamper script blob(s)"
                        ),
                        "done": True,
                    },
                )
            elif key == "masquerade":
                masquerade_blobs = future.result()
                yield (
                    "progress",
                    {
                        "step": "masquerade",
                        "label": f"Found {len(masquerade_blobs)} confirmed masquerade blob(s)",
                        "done": True,
                    },
                )
            elif key == "camouflage":
                camouflage_commits = future.result()
                yield (
                    "progress",
                    {
                        "step": "camouflage",
                        "label": f"Found {len(camouflage_commits)} camouflage commit(s)",
                        "done": True,
                    },
                )
            elif key == "vscode":
                vscode_findings = future.result()
                yield (
                    "progress",
                    {
                        "step": "vscode",
                        "label": f"Found {len(vscode_findings)} risky VS Code task(s)",
                        "done": True,
                    },
                )
            else:
                vscode_task_blobs = future.result()
                yield (
                    "progress",
                    {
                        "step": "vscode_history",
                        "label": f"Found {len(vscode_task_blobs)} historical risky tasks.json blob(s)",
                        "done": True,
                    },
                )

    line_findings, clock_tamper_blobs = blob_result
    blobs_affected = sorted({sha for sha, _, _ in line_findings})
    preview = [
        {"blob": sha[:12], "line": line_no, "text": line[:200].decode("utf-8", errors="replace")}
        for sha, line, line_no in line_findings[:20]
    ]
    clock_tamper_preview = [{"blob": sha[:12], "indicators": indicators} for sha, indicators in clock_tamper_blobs[:20]]
    masquerade_preview = [{"blob": sha[:12], "path": path} for sha, path in masquerade_blobs[:20]]
    camouflage_preview = [
        {
            "commit": f.commit[:12],
            "subject": f.subject,
            "files_changed": f.files_changed,
            "suspicious_new_files": f.suspicious_new_files,
        }
        for f in camouflage_commits
    ]
    vscode_preview = [
        {"file": f.file, "task_label": f.task_label, "reasons": f.reasons, "severity": f.severity}
        for f in vscode_findings
    ]
    vscode_task_blobs_preview = [{"blob": sha[:12], "path": path} for sha, path in vscode_task_blobs[:20]]

    yield (
        "done",
        {
            "findings_count": len(line_findings),
            "blobs_affected": len(blobs_affected),
            "preview": preview,
            "truncated": len(line_findings) > 20,
            "clock_tamper_blobs_count": len(clock_tamper_blobs),
            "clock_tamper_preview": clock_tamper_preview,
            "masquerade_blobs_count": len(masquerade_blobs),
            "masquerade_blobs": masquerade_preview,
            "camouflage_commits_count": len(camouflage_commits),
            "camouflage_commits": camouflage_preview,
            "vscode_tasks_count": len(vscode_findings),
            "vscode_tasks": vscode_preview,
            "vscode_task_blobs_count": len(vscode_task_blobs),
            "vscode_task_blobs": vscode_task_blobs_preview,
        },
    )


@app.post("/api/recover/analyze")
def recover_analyze(req: RecoveryAnalyzeRequest) -> JSONResponse:
    root = _validate_recovery_path(req.path)
    result = None
    for event, data in _run_recover_analyze(root):
        if event == "done":
            result = data
    return JSONResponse(result)


@app.post("/api/recover/analyze/stream")
def recover_analyze_stream(req: RecoveryAnalyzeRequest) -> StreamingResponse:
    root = _validate_recovery_path(req.path)

    def generate():
        for event, data in _run_recover_analyze(root):
            yield _sse(event, data)

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


def _run_recovery(root: Path, push: bool, token: str | None) -> Generator[tuple[str, dict], None, None]:
    """Mirror-clone `root` into a disposable tmpdir, rewrite history there,
    optionally force-push the result back to `root`'s own 'origin' remote,
    then always delete the disposable clone. Never modifies `root` itself --
    that's the whole point of working on a throwaway mirror.
    """
    tmpdir = Path(tempfile.mkdtemp(prefix="polinrider-guard-recover-"))
    try:
        yield ("progress", {"step": "mirror", "label": "Creating disposable mirror clone..."})
        clone_result = subprocess.run(
            ["git", "clone", "--mirror", str(root), str(tmpdir)],
            capture_output=True, text=True,
        )
        if clone_result.returncode != 0:
            yield ("error", {"message": f"mirror clone failed: {clone_result.stderr.strip()}"})
            return
        yield ("progress", {"step": "mirror", "label": "Mirror clone created", "done": True})

        patterns = recovery.load_patterns()

        yield ("progress", {"step": "analyze", "label": "Analyzing history..."})
        findings, clock_blobs = recovery.analyze_blobs(tmpdir, patterns)
        masquerade_blobs = recovery.find_masquerade_blobs(tmpdir)
        vscode_task_blobs = recovery.find_risky_vscode_task_blobs(tmpdir)
        if not findings and not clock_blobs and not masquerade_blobs and not vscode_task_blobs:
            yield (
                "progress",
                {
                    "step": "analyze",
                    "label": (
                        "No IOC/padding/clock-tamper/masquerade/historical-tasks.json matches "
                        "found -- nothing to clean"
                    ),
                    "done": True,
                },
            )
            yield (
                "done",
                {
                    "cleaned": False,
                    "findings_before": 0,
                    "blobs_affected": 0,
                    "clock_tamper_blobs": 0,
                    "masquerade_blobs": 0,
                    "vscode_task_blobs": 0,
                    "pushed": False,
                },
            )
            return
        blobs_affected = len({sha for sha, _, _ in findings})
        yield (
            "progress",
            {
                "step": "analyze",
                "label": (
                    f"Found {len(findings)} matching line(s) across {blobs_affected} blob(s), "
                    f"plus {len(clock_blobs)} whole clock-tamper script blob(s), "
                    f"{len(masquerade_blobs)} confirmed masquerade blob(s), and "
                    f"{len(vscode_task_blobs)} historical risky tasks.json blob(s)"
                ),
                "done": True,
            },
        )

        yield ("progress", {"step": "rewrite", "label": "Rewriting history via git-filter-repo..."})
        masquerade_shas = [sha for sha, _ in masquerade_blobs]
        vscode_task_shas = [sha for sha, _ in vscode_task_blobs]
        try:
            recovery.apply_clean(
                tmpdir,
                patterns,
                masquerade_shas=masquerade_shas,
                vscode_task_shas=vscode_task_shas,
                force_non_mirror=False,
            )
        except RuntimeError as exc:
            yield ("error", {"message": str(exc)})
            return
        yield ("progress", {"step": "rewrite", "label": "History rewritten", "done": True})

        yield ("progress", {"step": "verify", "label": "Verifying the payload is gone..."})
        remaining, remaining_clock_blobs = recovery.analyze_blobs(tmpdir, patterns)
        remaining_masquerade_blobs = recovery.find_masquerade_blobs(tmpdir)
        remaining_vscode_task_blobs = recovery.find_risky_vscode_task_blobs(tmpdir)
        if remaining or remaining_clock_blobs or remaining_masquerade_blobs or remaining_vscode_task_blobs:
            yield (
                "error",
                {
                    "message": (
                        f"{len(remaining)} line match(es), {len(remaining_clock_blobs)} clock-tamper "
                        f"blob(s), {len(remaining_masquerade_blobs)} masquerade blob(s), and "
                        f"{len(remaining_vscode_task_blobs)} risky tasks.json blob(s) still present "
                        "after rewrite -- aborting, nothing was pushed"
                    )
                },
            )
            return
        yield ("progress", {"step": "verify", "label": "Verified clean", "done": True})

        pushed = False
        origin_url = _get_origin_url(root)
        if push:
            if not origin_url:
                yield ("error", {"message": "push requested but the repo has no 'origin' remote configured"})
                return
            yield ("progress", {"step": "push", "label": f"Force-pushing to {origin_url}..."})
            push_url = (
                _inject_token(origin_url, token)
                if token and urlsplit(origin_url).scheme in ("http", "https")
                else origin_url
            )
            env = os.environ.copy()
            env["GIT_TERMINAL_PROMPT"] = "0"
            push_result = subprocess.run(
                ["git", "push", "--mirror", "--force", push_url],
                cwd=tmpdir, capture_output=True, text=True, env=env,
            )
            if push_result.returncode != 0:
                stderr = push_result.stderr.strip()[-2000:]
                if token:
                    stderr = stderr.replace(push_url, origin_url).replace(token, "***")
                yield ("error", {"message": f"push failed: {stderr}"})
                return
            pushed = True
            yield ("progress", {"step": "push", "label": "Pushed", "done": True})

        yield (
            "done",
            {
                "cleaned": True,
                "findings_before": len(findings),
                "blobs_affected": blobs_affected,
                "clock_tamper_blobs": len(clock_blobs),
                "masquerade_blobs": len(masquerade_blobs),
                "vscode_task_blobs": len(vscode_task_blobs),
                "pushed": pushed,
                "origin_url": origin_url,
            },
        )
    finally:
        _rmtree_force(tmpdir)


@app.post("/api/recover/apply")
def recover_apply(req: RecoveryApplyRequest) -> JSONResponse:
    root = _validate_recover_apply_request(req)

    result = None
    error_message = None
    for event, data in _run_recovery(root, req.push, req.token):
        if event == "done":
            result = data
        elif event == "error":
            error_message = data["message"]

    if error_message:
        raise HTTPException(400, error_message)
    return JSONResponse(result)


@app.post("/api/recover/apply/stream")
def recover_apply_stream(req: RecoveryApplyRequest) -> StreamingResponse:
    root = _validate_recover_apply_request(req)

    def generate():
        for event, data in _run_recovery(root, req.push, req.token):
            yield _sse(event, data)

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.post("/api/recover/remove-vscode-tasks")
def recover_remove_vscode_tasks(req: RecoveryRemoveTasksRequest) -> JSONResponse:
    """Edit risky .vscode/tasks.json in place in the scanned directory --
    the one Recovery action that touches the original path directly instead
    of a disposable mirror clone, since it's a working-tree config edit,
    not git-history surgery. See recovery.remove_risky_vscode_tasks()'s
    docstring for the full reasoning and its comment/formatting trade-off.
    """
    root = _validate_recover_remove_tasks_request(req)
    try:
        edited_files = recovery.remove_risky_vscode_tasks(root)
    except OSError as exc:
        raise HTTPException(
            400,
            f"could not write to {root}: {exc}. If you're running the Docker web UI, the "
            "scanned path is mounted read-only by default -- see the 'web' service's volumes "
            "in docker-compose.yml for how to make it writable, or run the local (non-Docker) "
            "install instead.",
        )
    return JSONResponse({"edited_files": edited_files, "edited_count": len(edited_files)})


MAX_FILE_VIEW_BYTES = 1_000_000  # 1MB cap -- a sane bound for "show me the file", not a file dump service


@app.get("/api/file")
def view_file(path: str, file: str) -> JSONResponse:
    """Read a single file's content for the browser's file viewer.

    `path` is a repo root already scanned (or being recovered); `file` is a
    path relative to it. Resolved and checked to land *inside* `path`, so
    this can't be used to read arbitrary files elsewhere on the host via a
    `../` (or an absolute-path) escape -- same trust boundary as local-path
    scanning itself, not a new one: it's read-only, and never leaves the
    loopback interface by default.
    """
    root = Path(path)
    if not root.exists() or not root.is_dir():
        raise HTTPException(400, f"path does not exist or is not a directory: {root}")
    root = root.resolve()

    if Path(file).is_absolute():
        raise HTTPException(400, "file must be a relative path")

    target = (root / file).resolve()
    try:
        target.relative_to(root)
    except ValueError:
        raise HTTPException(400, "file must be a path inside the scanned directory")
    if not target.exists() or not target.is_file():
        raise HTTPException(404, f"file not found: {file}")

    raw = target.read_bytes()
    if b"\x00" in raw[:8192]:
        return JSONResponse({"content": "", "binary": True, "truncated": False, "size": len(raw)})

    truncated = len(raw) > MAX_FILE_VIEW_BYTES
    content = raw[:MAX_FILE_VIEW_BYTES].decode("utf-8", errors="replace")
    return JSONResponse({"content": content, "binary": False, "truncated": truncated, "size": len(raw)})


def _list_windows_drives() -> list[dict]:
    import string

    drives = []
    for letter in string.ascii_uppercase:
        p = Path(f"{letter}:/")
        if p.exists():
            drives.append({"name": f"{letter}:\\", "path": str(p)})
    return drives


@app.get("/api/browse")
def browse(path: str | None = None) -> JSONResponse:
    """List subdirectories of `path` for the local-path picker.

    Browsers deliberately don't expose a real filesystem path for a folder
    picked via <input type=file webkitdirectory> or showDirectoryPicker(),
    so a client-side "browse" control can't fill in a path the backend can
    actually scan. This lists directories server-side instead -- same trust
    boundary as local-path scanning itself (see module docstring): it's
    read-only and never leaves the loopback interface by default.
    """
    # Explicit empty string (not the "no path given" default) means "show
    # Windows drives", the pseudo-root above C:\, D:\, etc.
    if path == "" and os.name == "nt":
        return JSONResponse({"path": "", "parent": None, "dirs": _list_windows_drives()})

    if path:
        root = Path(path)
    elif Path("/scan").is_dir():
        root = Path("/scan")
    else:
        root = Path.cwd()

    try:
        root = root.resolve(strict=True)
    except OSError:
        raise HTTPException(400, f"cannot open path: {path}")
    if not root.is_dir():
        raise HTTPException(400, f"not a directory: {root}")

    try:
        children = sorted(root.iterdir(), key=lambda p: p.name.lower())
    except PermissionError:
        raise HTTPException(403, f"permission denied: {root}")

    dirs = []
    for child in children:
        try:
            if child.is_dir():
                dirs.append({"name": child.name, "path": str(child)})
        except OSError:
            continue  # broken symlink, permission error mid-listing, etc.

    if root.parent == root:
        # filesystem root ("/" on POSIX, a drive root like "C:\" on Windows)
        parent = "" if os.name == "nt" else None
    else:
        parent = str(root.parent)

    return JSONResponse({"path": str(root), "parent": parent, "dirs": dirs})


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


def _parse_args(argv: list[str] | None = None):
    import argparse

    parser = argparse.ArgumentParser(
        prog="polinrider-guard-web",
        description="Run the polinrider-guard web UI (paste a git URL, get a report).",
    )
    parser.add_argument("--host", default="127.0.0.1", help="default: 127.0.0.1 (localhost only)")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument(
        "--batch-workers",
        type=int,
        default=BATCH_SCAN_MAX_WORKERS,
        help=(
            "how many repos the 'scan all repos under this path' feature scans "
            f"concurrently (default: {BATCH_SCAN_MAX_WORKERS}); each repo's own scan "
            "already runs its six scanners concurrently, so raise this only if you "
            "have the cores/disk throughput to back it"
        ),
    )
    args = parser.parse_args(argv)
    if args.batch_workers < 1:
        parser.error("--batch-workers must be at least 1")
    return args


def main(argv: list[str] | None = None) -> None:
    import uvicorn

    global BATCH_SCAN_MAX_WORKERS

    args = _parse_args(argv)
    BATCH_SCAN_MAX_WORKERS = args.batch_workers

    # uvicorn logs the bind address verbatim, so with --host 0.0.0.0 (e.g.
    # from Docker) it prints "http://0.0.0.0:8765" -- not a URL a browser
    # can actually open. Print the real one to click instead.
    browse_host = "localhost" if args.host in ("0.0.0.0", "::") else args.host
    # flush=True: stdout is fully buffered (not line-buffered) when there's
    # no TTY, e.g. under Docker/compose -- without it this sits unseen in
    # the buffer for as long as the server runs.
    print(f"polinrider-guard-web: open http://{browse_host}:{args.port}", flush=True)
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print(
            "polinrider-guard-web: WARNING -- bound to a non-loopback host. "
            "This server clones whatever git URL it's given, can read whatever "
            "local path it's given, and lets the browser walk its directory tree "
            "(the local-path picker); put your own auth in front of it if this "
            "port is reachable by anyone you don't trust.",
            flush=True,
        )

    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
