import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

git_filter_repo = pytest.importorskip("git_filter_repo")
fastapi_testclient = pytest.importorskip("fastapi.testclient")

from polinrider_guard import webapp  # noqa: E402
from polinrider_guard.webapp import app  # noqa: E402

TestClient = fastapi_testclient.TestClient


def _git(repo, *args):
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


def _make_repo_with_buried_payload(base: Path, name: str = "origin") -> Path:
    repo = base / name
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "T")

    (repo / "app.js").write_text('console.log("hello");\n')
    _git(repo, "add", "app.js")
    _git(repo, "commit", "-q", "-m", "legit commit 1")

    (repo / "app.js").write_text(
        'console.log("hello");\n'
        'global["_V"]="8-st*";\n'
        'fetch("https://trongrid.io/x");\n'
    )
    _git(repo, "add", "app.js")
    _git(repo, "commit", "-q", "-m", "malicious injection")

    (repo / "app.js").write_text(
        'console.log("hello");\n'
        'global["_V"]="8-st*";\n'
        'fetch("https://trongrid.io/x");\n'
        'console.log("feature added");\n'
    )
    _git(repo, "add", "app.js")
    _git(repo, "commit", "-q", "-m", "legit commit on top")
    return repo


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


def test_recover_analyze_finds_buried_payload(tmp_path, client):
    repo = _make_repo_with_buried_payload(tmp_path)
    resp = client.post("/api/recover/analyze", json={"path": str(repo)})
    assert resp.status_code == 200
    data = resp.json()
    assert data["findings_count"] == 4  # 2 IOC lines x 2 blobs
    assert data["blobs_affected"] == 2
    assert len(data["preview"]) == 4


def test_recover_analyze_clean_repo(tmp_path, client):
    repo = tmp_path / "clean"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "T")
    (repo / "a.txt").write_text("hello\n")
    _git(repo, "add", "a.txt")
    _git(repo, "commit", "-q", "-m", "init")

    resp = client.post("/api/recover/analyze", json={"path": str(repo)})
    assert resp.status_code == 200
    assert resp.json()["findings_count"] == 0


def test_recover_analyze_rejects_non_git_path(tmp_path, client):
    (tmp_path / "notgit").mkdir()
    resp = client.post("/api/recover/analyze", json={"path": str(tmp_path / "notgit")})
    assert resp.status_code == 400


def test_recover_apply_rejects_wrong_confirm_phrase(tmp_path, client):
    repo = _make_repo_with_buried_payload(tmp_path)
    resp = client.post("/api/recover/apply", json={"path": str(repo), "confirm": "yes please"})
    assert resp.status_code == 400
    assert "REWRITE HISTORY" in resp.json()["detail"]


def test_recover_apply_rejects_push_without_push_confirm(tmp_path, client):
    repo = _make_repo_with_buried_payload(tmp_path)
    resp = client.post(
        "/api/recover/apply",
        json={"path": str(repo), "confirm": "REWRITE HISTORY", "push": True, "push_confirm": "sure"},
    )
    assert resp.status_code == 400
    assert "FORCE PUSH" in resp.json()["detail"]


def test_recover_apply_without_push_cleans_and_leaves_original_untouched(tmp_path, client):
    repo = _make_repo_with_buried_payload(tmp_path)
    original_content = (repo / "app.js").read_text()

    resp = client.post("/api/recover/apply", json={"path": str(repo), "confirm": "REWRITE HISTORY"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["cleaned"] is True
    assert data["findings_before"] == 4
    assert data["pushed"] is False

    # The directory that was scanned is never touched directly -- the
    # disposable mirror clone did all the work and was thrown away.
    assert (repo / "app.js").read_text() == original_content
    assert "trongrid.io" in original_content


def test_recover_apply_stream_emits_progress_then_done(tmp_path, client):
    repo = _make_repo_with_buried_payload(tmp_path)
    resp = client.post(
        "/api/recover/apply/stream", json={"path": str(repo), "confirm": "REWRITE HISTORY"}
    )
    assert resp.status_code == 200
    events = _collect_sse(resp)
    assert events[-1][0] == "done"
    assert events[-1][1]["cleaned"] is True
    steps_seen = {data["step"] for event, data in events if event == "progress"}
    assert steps_seen == {"mirror", "analyze", "rewrite", "verify"}


def test_recover_analyze_finds_padding_hidden_line(tmp_path, client):
    # No literal IOC pattern here -- only scan_padding's whitespace-run
    # signal, confirming recovery.py catches it even without a known
    # byte-signature match.
    repo = tmp_path / "padded"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "T")
    (repo / "eslint.config.mjs").write_text(
        "export default [];" + " " * 100 + 'console.log("hidden marker");\n'
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "add config")

    resp = client.post("/api/recover/analyze", json={"path": str(repo)})
    assert resp.status_code == 200
    data = resp.json()
    assert data["findings_count"] == 1
    assert data["blobs_affected"] == 1


def test_recover_analyze_finds_clock_tamper_blob(tmp_path, client):
    repo = tmp_path / "clocktamper"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "T")
    (repo / "config.bat").write_text(
        "date %LAST_COMMIT_DATE%\n"
        "git commit --amend -m x --no-verify\n"
        "git push -uf origin main --no-verify\n"
    )
    _git(repo, "add", "config.bat")
    _git(repo, "commit", "-q", "-m", "add tooling")

    resp = client.post("/api/recover/analyze", json={"path": str(repo)})
    assert resp.status_code == 200
    data = resp.json()
    assert data["clock_tamper_blobs_count"] == 1
    assert "date" in data["clock_tamper_preview"][0]["indicators"][0].lower()


def test_recover_apply_blanks_clock_tamper_script_and_leaves_legit_content(tmp_path, client):
    repo = tmp_path / "clocktamper2"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "T")
    (repo / "config.bat").write_text(
        "date %LAST_COMMIT_DATE%\ngit commit --amend -m x --no-verify\n"
    )
    (repo / "app.js").write_text('console.log("legit");\n')
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "add tooling and app")

    resp = client.post("/api/recover/apply", json={"path": str(repo), "confirm": "REWRITE HISTORY"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["cleaned"] is True
    assert data["clock_tamper_blobs"] == 1

    # Re-analyzing a fresh mirror of the (untouched) original still finds
    # it -- the fix only ever lived in the disposable copy, as designed.
    resp2 = client.post("/api/recover/analyze", json={"path": str(repo)})
    assert resp2.json()["clock_tamper_blobs_count"] == 1


def test_recover_analyze_reports_camouflage_commit(tmp_path, client):
    repo = tmp_path / "camouflage"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "T")

    for i in range(45):
        (repo / f"file{i}.ts").write_text(f"export const v{i} = {i};\n" * 3)
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "initial commit")

    for i in range(45):
        (repo / f"file{i}.ts").write_text(f"export const v{i} = {i}; \n" * 3)
    (repo / "config.bat").write_text("@echo off\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "return back")

    resp = client.post("/api/recover/analyze", json={"path": str(repo)})
    assert resp.status_code == 200
    data = resp.json()
    assert data["camouflage_commits_count"] == 1
    assert data["camouflage_commits"][0]["subject"] == "return back"
    assert "config.bat" in data["camouflage_commits"][0]["suspicious_new_files"]


def test_recover_analyze_finds_masquerade_blob(tmp_path, client):
    repo = tmp_path / "masq"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "T")
    (repo / "assets").mkdir()
    (repo / "assets" / "icon.woff2").write_bytes(b"function evil(){require('fs')}")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "add icon")

    resp = client.post("/api/recover/analyze", json={"path": str(repo)})
    assert resp.status_code == 200
    data = resp.json()
    assert data["masquerade_blobs_count"] == 1
    assert data["masquerade_blobs"][0]["path"] == "assets/icon.woff2"


def test_recover_analyze_does_not_flag_weak_tier_masquerade(tmp_path, client):
    repo = tmp_path / "masqweak"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "T")
    (repo / "assets").mkdir()
    (repo / "assets" / "weird.woff2").write_bytes(b"\x01\x02\x03not a real font header, just noise bytes")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "add weird font")

    resp = client.post("/api/recover/analyze", json={"path": str(repo)})
    assert resp.status_code == 200
    assert resp.json()["masquerade_blobs_count"] == 0


def test_recover_apply_blanks_masquerade_blob_and_leaves_legit_content(tmp_path, client):
    repo = tmp_path / "masqapply"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "T")
    (repo / "assets").mkdir()
    (repo / "assets" / "icon.woff2").write_bytes(b"function evil(){require('fs')}")
    (repo / "app.js").write_text('console.log("legit");\n')
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "add icon and app")

    resp = client.post("/api/recover/apply", json={"path": str(repo), "confirm": "REWRITE HISTORY"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["cleaned"] is True
    assert data["masquerade_blobs"] == 1

    # Re-analyzing a fresh mirror of the (untouched) original still finds
    # it -- the fix only ever lived in the disposable copy, as designed.
    resp2 = client.post("/api/recover/analyze", json={"path": str(repo)})
    assert resp2.json()["masquerade_blobs_count"] == 1


def test_recover_analyze_finds_historical_vscode_task_blob(tmp_path, client):
    repo = tmp_path / "vscodehistory"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "T")
    vscode_dir = repo / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "tasks.json").write_text(
        '{"tasks": [{"label": "format-check", "command": "node", "args": ["a.woff2"],'
        ' "runOptions": {"runOn": "folderOpen"}, "hide": true}]}\n'
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "add risky tasks.json")

    (vscode_dir / "tasks.json").write_text(
        '{"tasks": [{"label": "legit-build", "command": "npm", "args": ["run", "build"]}]}\n'
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "fix tasks.json on tip")

    resp = client.post("/api/recover/analyze", json={"path": str(repo)})
    assert resp.status_code == 200
    data = resp.json()
    # Current tree is already clean...
    assert data["vscode_tasks_count"] == 0
    # ...but the old commit's blob is still recoverable from history.
    assert data["vscode_task_blobs_count"] == 1
    assert data["vscode_task_blobs"][0]["path"] == ".vscode/tasks.json"


def test_recover_apply_blanks_historical_vscode_task_blob(tmp_path, client):
    repo = tmp_path / "vscodehistoryapply"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "T")
    vscode_dir = repo / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "tasks.json").write_text(
        '{"tasks": [{"label": "format-check", "command": "node", "args": ["a.woff2"],'
        ' "runOptions": {"runOn": "folderOpen"}, "hide": true}]}\n'
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "add risky tasks.json")

    (vscode_dir / "tasks.json").write_text(
        '{"tasks": [{"label": "legit-build", "command": "npm", "args": ["run", "build"]}]}\n'
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "fix tasks.json on tip")

    resp = client.post("/api/recover/apply", json={"path": str(repo), "confirm": "REWRITE HISTORY"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["cleaned"] is True
    assert data["vscode_task_blobs"] == 1

    # The originally-scanned repo is untouched -- re-analyzing it still
    # finds the old blob, since the fix only ever lived in the disposable
    # mirror clone.
    resp2 = client.post("/api/recover/analyze", json={"path": str(repo)})
    assert resp2.json()["vscode_task_blobs_count"] == 1


def test_recover_analyze_reports_risky_vscode_task(tmp_path, client):
    repo = tmp_path / "vscodetask"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "T")
    vscode_dir = repo / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "tasks.json").write_text(
        '{"tasks": [{"label": "format-check", "command": "node", "args": ["a.woff2"],'
        ' "runOptions": {"runOn": "folderOpen"}, "hide": true}]}\n'
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "add tasks.json")

    resp = client.post("/api/recover/analyze", json={"path": str(repo)})
    assert resp.status_code == 200
    data = resp.json()
    assert data["vscode_tasks_count"] == 1
    assert data["vscode_tasks"][0]["task_label"] == "format-check"

    # Report-only: applying should not touch it or count it as "cleaned".
    resp2 = client.post("/api/recover/apply", json={"path": str(repo), "confirm": "REWRITE HISTORY"})
    assert resp2.status_code == 200
    assert (repo / ".vscode" / "tasks.json").exists()


def test_recover_remove_vscode_tasks_keeps_legit_task(tmp_path, client):
    repo = tmp_path / "vscoderemove"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "T")
    vscode_dir = repo / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "tasks.json").write_text(
        '{"tasks": ['
        '{"label": "format-check", "command": "node", "args": ["a.woff2"],'
        ' "runOptions": {"runOn": "folderOpen"}, "hide": true},'
        '{"label": "legit-build", "command": "npm", "args": ["run", "build"]}'
        ']}\n'
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "add tasks.json")

    resp = client.post(
        "/api/recover/remove-vscode-tasks", json={"path": str(repo), "confirm": "REMOVE TASK"}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["edited_count"] == 1

    resp2 = client.post("/api/recover/analyze", json={"path": str(repo)})
    assert resp2.json()["vscode_tasks_count"] == 0

    import json as jsonlib
    remaining = jsonlib.loads((vscode_dir / "tasks.json").read_text())
    assert [t["label"] for t in remaining["tasks"]] == ["legit-build"]


def test_recover_remove_vscode_tasks_rejects_wrong_confirm_phrase(tmp_path, client):
    repo = tmp_path / "vscoderemovebad"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "T")
    (repo / "a.txt").write_text("hello\n")
    _git(repo, "add", "a.txt")
    _git(repo, "commit", "-q", "-m", "init")

    resp = client.post(
        "/api/recover/remove-vscode-tasks", json={"path": str(repo), "confirm": "nope"}
    )
    assert resp.status_code == 400
    assert "REMOVE TASK" in resp.json()["detail"]


def test_recover_remove_vscode_tasks_reports_readonly_mount_clearly(tmp_path, client, monkeypatch):
    # Regression test: the Docker web UI mounts the scanned path read-only
    # by default (docker-compose.yml), and this is the one Recovery action
    # that writes to it directly. It must fail with a clear 400, not crash
    # with an unhandled 500 -- reproduced here by forcing the same OSError
    # a real read-only filesystem raises, without needing an actual
    # read-only mount in the test environment.
    repo = tmp_path / "vscoderemoteonly"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "T")
    vscode_dir = repo / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "tasks.json").write_text(
        '{"tasks": [{"label": "format-check", "command": "node", "args": ["a.woff2"],'
        ' "runOptions": {"runOn": "folderOpen"}, "hide": true}]}\n'
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "add tasks.json")

    from polinrider_guard import recovery as recovery_module

    def _raise_readonly(*args, **kwargs):
        raise OSError(30, "Read-only file system")

    monkeypatch.setattr(recovery_module, "remove_risky_vscode_tasks", _raise_readonly)

    resp = client.post(
        "/api/recover/remove-vscode-tasks", json={"path": str(repo), "confirm": "REMOVE TASK"}
    )
    assert resp.status_code == 400
    assert "read-only" in resp.json()["detail"].lower()


def test_recover_remove_vscode_tasks_no_findings_returns_zero(tmp_path, client):
    repo = tmp_path / "vscoderemoveclean"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "T")
    (repo / "a.txt").write_text("hello\n")
    _git(repo, "add", "a.txt")
    _git(repo, "commit", "-q", "-m", "init")

    resp = client.post(
        "/api/recover/remove-vscode-tasks", json={"path": str(repo), "confirm": "REMOVE TASK"}
    )
    assert resp.status_code == 200
    assert resp.json()["edited_count"] == 0


def test_recover_apply_with_push_updates_real_origin(tmp_path, client):
    # A bare repo standing in for "the real remote" -- origin points at it.
    bare = tmp_path / "bare.git"
    subprocess.run(["git", "init", "-q", "--bare", str(bare)], check=True, capture_output=True)

    repo = _make_repo_with_buried_payload(tmp_path, name="work")
    _git(repo, "remote", "add", "origin", str(bare))
    _git(repo, "push", "-q", "origin", "HEAD:refs/heads/main")

    resp = client.post(
        "/api/recover/apply",
        json={
            "path": str(repo),
            "confirm": "REWRITE HISTORY",
            "push": True,
            "push_confirm": "FORCE PUSH",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["cleaned"] is True
    assert data["pushed"] is True
    assert data["origin_url"] == str(bare)

    # The real remote now has the cleaned history.
    show = subprocess.run(
        ["git", "show", "refs/heads/main:app.js"], cwd=bare, capture_output=True, text=True, check=True
    )
    assert "trongrid.io" not in show.stdout
    assert "feature added" in show.stdout

    # The originally-scanned working copy is still untouched/still dirty --
    # only the disposable mirror and the real remote were affected.
    assert "trongrid.io" in (repo / "app.js").read_text()


# --- /api/file --------------------------------------------------------------


def test_view_file_returns_content(tmp_path, client):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.js").write_bytes(b"line1\nline2\nline3\n")

    resp = client.get("/api/file", params={"path": str(repo), "file": "app.js"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["content"] == "line1\nline2\nline3\n"
    assert data["binary"] is False
    assert data["truncated"] is False


def test_view_file_nested_path(tmp_path, client):
    repo = tmp_path / "repo"
    (repo / "sub" / "dir").mkdir(parents=True)
    (repo / "sub" / "dir" / "f.txt").write_bytes(b"nested content\n")

    resp = client.get("/api/file", params={"path": str(repo), "file": "sub/dir/f.txt"})
    assert resp.status_code == 200
    assert resp.json()["content"] == "nested content\n"


def test_view_file_detects_binary(tmp_path, client):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "bin.dat").write_bytes(b"\x00\x01\x02binary")

    resp = client.get("/api/file", params={"path": str(repo), "file": "bin.dat"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["binary"] is True
    assert data["content"] == ""


def test_view_file_rejects_path_traversal(tmp_path, client):
    repo = tmp_path / "repo"
    repo.mkdir()
    (tmp_path / "outside.txt").write_text("secret")

    resp = client.get("/api/file", params={"path": str(repo), "file": "../outside.txt"})
    assert resp.status_code == 400


def test_view_file_rejects_absolute_path(tmp_path, client):
    repo = tmp_path / "repo"
    repo.mkdir()
    resp = client.get("/api/file", params={"path": str(repo), "file": "/etc/passwd"})
    assert resp.status_code == 400


def test_view_file_404_on_missing_file(tmp_path, client):
    repo = tmp_path / "repo"
    repo.mkdir()
    resp = client.get("/api/file", params={"path": str(repo), "file": "nope.txt"})
    assert resp.status_code == 404


def test_view_file_400_on_missing_repo(tmp_path, client):
    resp = client.get("/api/file", params={"path": str(tmp_path / "nope"), "file": "a.txt"})
    assert resp.status_code == 400


# --- URL-scan clone persistence ----------------------------------------------


def test_url_scan_persists_clone_and_replaces_it_on_next_scan(tmp_path):
    # _run_scan doesn't itself validate the URL scheme (the HTTP endpoint's
    # _validate_request does that) -- calling it directly lets this test
    # exercise real clone-persistence behavior against a local source repo,
    # with no network access required.
    source = tmp_path / "source"
    source.mkdir()
    _git(source, "init", "-q")
    _git(source, "config", "user.email", "t@example.com")
    _git(source, "config", "user.name", "T")
    (source / "a.txt").write_text("hello\n")
    _git(source, "add", "a.txt")
    _git(source, "commit", "-q", "-m", "init")

    webapp._last_scan_clone = None
    try:
        events = list(webapp._run_scan(str(source), None, None, None))
        done = [data for event, data in events if event == "done"]
        assert len(done) == 1
        clone_dir_1 = Path(done[0]["source_path"])
        assert clone_dir_1.exists()
        assert (clone_dir_1 / "a.txt").exists()
        # Persisted after scanning -- not deleted the moment scanning ends.
        assert webapp._last_scan_clone == clone_dir_1

        # A second URL scan replaces (and cleans up) the first clone.
        events2 = list(webapp._run_scan(str(source), None, None, None))
        done2 = [data for event, data in events2 if event == "done"]
        clone_dir_2 = Path(done2[0]["source_path"])
        assert clone_dir_2 != clone_dir_1
        assert not clone_dir_1.exists()
        assert clone_dir_2.exists()
    finally:
        if webapp._last_scan_clone is not None and webapp._last_scan_clone.exists():
            webapp._rmtree_force(webapp._last_scan_clone)
        webapp._last_scan_clone = None


def test_path_scan_does_not_touch_last_scan_clone_state(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "T")
    (repo / "a.txt").write_text("hello\n")
    _git(repo, "add", "a.txt")
    _git(repo, "commit", "-q", "-m", "init")

    webapp._last_scan_clone = None
    events = list(webapp._run_scan(None, None, str(repo), None))
    done = [data for event, data in events if event == "done"]
    assert done[0]["source_path"] == str(repo.resolve())
    assert webapp._last_scan_clone is None
