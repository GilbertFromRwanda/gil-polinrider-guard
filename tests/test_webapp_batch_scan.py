import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

fastapi_testclient = pytest.importorskip("fastapi.testclient")

from polinrider_guard import webapp  # noqa: E402
from polinrider_guard.webapp import app  # noqa: E402

TestClient = fastapi_testclient.TestClient


def _git(repo, *args):
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


def _init_repo(repo):
    repo.mkdir(parents=True)
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test User")


def _collect_sse(response) -> list[tuple[str, dict]]:
    import json as jsonlib

    events = []
    text = response.text
    for block in text.strip().split("\n\n"):
        if not block.strip():
            continue
        event_line, data_line = block.split("\n", 1)
        event = event_line.removeprefix("event: ")
        data = jsonlib.loads(data_line.removeprefix("data: "))
        events.append((event, data))
    return events


@pytest.fixture
def client():
    return TestClient(app)


# --- _iter_git_repos ---------------------------------------------------------


def test_iter_git_repos_finds_nested_and_skips_non_repos(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    _init_repo(workspace / "repo-a")
    (workspace / "repo-a" / "a.txt").write_text("hi\n")
    _git(workspace / "repo-a", "add", ".")
    _git(workspace / "repo-a", "commit", "-q", "-m", "init")

    _init_repo(workspace / "nested" / "repo-b")
    (workspace / "nested" / "repo-b" / "b.txt").write_text("hi\n")
    _git(workspace / "nested" / "repo-b", "add", ".")
    _git(workspace / "nested" / "repo-b", "commit", "-q", "-m", "init")

    (workspace / "not-a-repo" / "subdir").mkdir(parents=True)
    (workspace / "not-a-repo" / "subdir" / "file.txt").write_text("plain file\n")

    found = sorted(webapp._iter_git_repos(workspace))
    assert found == sorted([workspace / "repo-a", workspace / "nested" / "repo-b"])


def test_iter_git_repos_does_not_descend_into_a_found_repo(tmp_path):
    # A repo-inside-a-repo (e.g. a vendored/checked-out copy) should not be
    # reported as a second, separate scan target -- once the outer
    # directory is identified as a repo, its own subdirectories are not
    # walked further.
    workspace = tmp_path / "workspace"
    outer = workspace / "outer"
    _init_repo(outer)
    (outer / "a.txt").write_text("hi\n")
    _git(outer, "add", ".")
    _git(outer, "commit", "-q", "-m", "init")

    inner = outer / "vendored" / "inner-repo"
    _init_repo(inner)
    (inner / "b.txt").write_text("hi\n")
    _git(inner, "add", ".")
    _git(inner, "commit", "-q", "-m", "init")

    found = list(webapp._iter_git_repos(workspace))
    assert found == [outer]


def test_iter_git_repos_skips_node_modules(tmp_path):
    workspace = tmp_path / "workspace"
    nested = workspace / "app" / "node_modules" / "some-pkg"
    _init_repo(nested)
    (nested / "x.txt").write_text("hi\n")
    _git(nested, "add", ".")
    _git(nested, "commit", "-q", "-m", "init")

    assert list(webapp._iter_git_repos(workspace)) == []


def test_iter_git_repos_empty_dir(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    assert list(webapp._iter_git_repos(workspace)) == []


def test_iter_git_repos_root_itself_is_a_repo(tmp_path):
    _init_repo(tmp_path / "repo")
    repo = tmp_path / "repo"
    (repo / "a.txt").write_text("hi\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "init")

    assert list(webapp._iter_git_repos(repo)) == [repo]


# --- /api/batch-scan ----------------------------------------------------------


def test_batch_scan_finds_and_scans_multiple_repos(tmp_path, client):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    clean_repo = workspace / "clean-repo"
    _init_repo(clean_repo)
    (clean_repo / "a.txt").write_text("hello\n")
    _git(clean_repo, "add", ".")
    _git(clean_repo, "commit", "-q", "-m", "init")

    dirty_repo = workspace / "dirty-repo"
    _init_repo(dirty_repo)
    (dirty_repo / "assets").mkdir()
    (dirty_repo / "assets" / "icon.woff2").write_bytes(b"function evil(){require('fs')}")
    _git(dirty_repo, "add", ".")
    _git(dirty_repo, "commit", "-q", "-m", "add masquerade")

    resp = client.post("/api/batch-scan", json={"path": str(workspace)})
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_repos"] == 2
    assert data["dirty_repos"] == 1
    assert data["total_findings"] == 1
    assert data["truncated"] is False

    by_path = {r["source_path"]: r for r in data["repos"]}
    dirty_report = by_path[str(dirty_repo.resolve())]
    assert dirty_report["summary"]["total_findings"] == 1
    clean_report = by_path[str(clean_repo.resolve())]
    assert clean_report["summary"]["total_findings"] == 0


def test_batch_scan_no_repos_found(tmp_path, client):
    workspace = tmp_path / "empty-workspace"
    workspace.mkdir()

    resp = client.post("/api/batch-scan", json={"path": str(workspace)})
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_repos"] == 0
    assert data["repos"] == []


def test_batch_scan_rejects_nonexistent_path(tmp_path, client):
    resp = client.post("/api/batch-scan", json={"path": str(tmp_path / "does-not-exist")})
    assert resp.status_code == 400


def test_batch_scan_rejects_file_path(tmp_path, client):
    f = tmp_path / "somefile.txt"
    f.write_text("hi\n")
    resp = client.post("/api/batch-scan", json={"path": str(f)})
    assert resp.status_code == 400


def test_batch_scan_stream_emits_discover_and_repo_progress(tmp_path, client):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repo = workspace / "repo-a"
    _init_repo(repo)
    (repo / "a.txt").write_text("hi\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "init")

    resp = client.post("/api/batch-scan/stream", json={"path": str(workspace)})
    assert resp.status_code == 200
    events = _collect_sse(resp)

    assert events[-1][0] == "done"
    assert events[-1][1]["total_repos"] == 1

    discover_events = [d for e, d in events if e == "progress" and d.get("step") == "discover"]
    assert any(d.get("done") and d.get("repos") for d in discover_events)

    repo_events = [d for e, d in events if e == "progress" and d.get("step") == "repo"]
    assert any(d.get("done") for d in repo_events)


# --- --batch-workers CLI flag -------------------------------------------------


def test_parse_args_batch_workers_default_matches_module_constant():
    args = webapp._parse_args([])
    assert args.batch_workers == webapp.BATCH_SCAN_MAX_WORKERS


def test_parse_args_accepts_custom_batch_workers():
    args = webapp._parse_args(["--batch-workers", "16"])
    assert args.batch_workers == 16


def test_parse_args_rejects_non_positive_batch_workers():
    with pytest.raises(SystemExit):
        webapp._parse_args(["--batch-workers", "0"])
    with pytest.raises(SystemExit):
        webapp._parse_args(["--batch-workers", "-1"])


def test_main_sets_module_level_batch_workers(monkeypatch):
    ran_with = {}

    def fake_uvicorn_run(app_obj, host, port):
        ran_with["host"] = host
        ran_with["port"] = port

    import uvicorn

    monkeypatch.setattr(uvicorn, "run", fake_uvicorn_run)
    original = webapp.BATCH_SCAN_MAX_WORKERS
    try:
        webapp.main(["--batch-workers", "12"])
        assert webapp.BATCH_SCAN_MAX_WORKERS == 12
        assert ran_with == {"host": "127.0.0.1", "port": 8765}
    finally:
        webapp.BATCH_SCAN_MAX_WORKERS = original
