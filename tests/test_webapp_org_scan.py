import subprocess
import sys
import urllib.error
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


# --- _parse_github_org_root ---------------------------------------------------


@pytest.mark.parametrize(
    "url, expected",
    [
        ("https://github.com/some-org", "some-org"),
        ("https://github.com/some-org/", "some-org"),
        ("http://github.com/some-org", "some-org"),
        ("https://www.github.com/some-org", "some-org"),
        ("git@github.com:some-org", "some-org"),
        ("https://github.com/some-org/some-repo", None),
        ("https://github.com/some-org/some-repo.git", None),
        ("git@github.com:some-org/some-repo.git", None),
        ("https://gitlab.com/some-org", None),
        ("not a url", None),
        ("https://github.com/", None),
    ],
)
def test_parse_github_org_root(url, expected):
    assert webapp._parse_github_org_root(url) == expected


# --- _list_github_repos --------------------------------------------------------


def test_list_github_repos_falls_back_to_user_endpoint_when_org_404s(monkeypatch):
    calls = []

    def fake_get(path, token):
        calls.append(path)
        if path.startswith("/orgs/"):
            raise urllib.error.HTTPError(path, 404, "Not Found", {}, None)
        assert path.startswith("/users/")
        return [{"clone_url": "https://example.invalid/a.git", "full_name": "someone/a"}]

    monkeypatch.setattr(webapp, "_github_api_get", fake_get)
    repos = webapp._list_github_repos("someone", None)
    assert [r["full_name"] for r in repos] == ["someone/a"]
    assert calls[0].startswith("/orgs/")
    assert calls[-1].startswith("/users/")


def test_list_github_repos_raises_404_when_neither_endpoint_has_it(monkeypatch):
    def fake_get(path, token):
        raise urllib.error.HTTPError(path, 404, "Not Found", {}, None)

    monkeypatch.setattr(webapp, "_github_api_get", fake_get)
    with pytest.raises(Exception) as exc_info:
        webapp._list_github_repos("nobody-here", None)
    assert "nobody-here" in str(exc_info.value)


def test_list_github_repos_propagates_non_404_errors(monkeypatch):
    import io

    def fake_get(path, token):
        if path.startswith("/orgs/"):
            err = urllib.error.HTTPError(path, 403, "Forbidden", {}, io.BytesIO(b"rate limited"))
            raise err
        raise AssertionError("should not fall back to /users/ on a non-404 error")

    monkeypatch.setattr(webapp, "_github_api_get", fake_get)
    with pytest.raises(Exception) as exc_info:
        webapp._list_github_repos("some-org", None)
    assert "403" in str(exc_info.value) or "rate limited" in str(exc_info.value)


# --- /api/org-scan --------------------------------------------------------------


def test_org_scan_clones_scans_and_discards_each_repo(tmp_path, client, monkeypatch):
    clean_repo = tmp_path / "clean-repo"
    _init_repo(clean_repo)
    (clean_repo / "a.txt").write_text("hello\n")
    _git(clean_repo, "add", ".")
    _git(clean_repo, "commit", "-q", "-m", "init")

    dirty_repo = tmp_path / "dirty-repo"
    _init_repo(dirty_repo)
    (dirty_repo / "assets").mkdir()
    (dirty_repo / "assets" / "icon.woff2").write_bytes(b"function evil(){require('fs')}")
    _git(dirty_repo, "add", ".")
    _git(dirty_repo, "commit", "-q", "-m", "add masquerade")

    def fake_list(login, token):
        assert login == "some-org"
        return [
            {"clone_url": str(clean_repo), "full_name": "some-org/clean-repo"},
            {"clone_url": str(dirty_repo), "full_name": "some-org/dirty-repo"},
        ]

    monkeypatch.setattr(webapp, "_list_github_repos", fake_list)

    resp = client.post("/api/org-scan", json={"org": "some-org"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["root"] == "some-org"
    assert data["total_repos"] == 2
    assert data["dirty_repos"] == 1
    assert data["total_findings"] == 1
    assert data["truncated"] is False

    by_name = {r["repo_name"]: r for r in data["repos"]}
    assert by_name["some-org/dirty-repo"]["summary"]["total_findings"] == 1
    assert by_name["some-org/clean-repo"]["summary"]["total_findings"] == 0

    # Ephemeral: no source_path is set, since each repo's clone is deleted
    # right after it's scanned -- unlike a local batch scan, there's no
    # live directory left for Recovery/the file viewer to point at.
    for r in data["repos"]:
        assert "source_path" not in r
        assert r["source_url"] in (str(clean_repo), str(dirty_repo))


def test_org_scan_no_repos_found(client, monkeypatch):
    monkeypatch.setattr(webapp, "_list_github_repos", lambda login, token: [])

    resp = client.post("/api/org-scan", json={"org": "empty-org"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_repos"] == 0
    assert data["repos"] == []


def test_org_scan_rejects_empty_org(client):
    resp = client.post("/api/org-scan", json={"org": "  "})
    assert resp.status_code == 400


def test_org_scan_surfaces_listing_error_as_400(client, monkeypatch):
    from fastapi import HTTPException

    def fake_list(login, token):
        raise HTTPException(404, f"no GitHub org or user account named '{login}'")

    monkeypatch.setattr(webapp, "_list_github_repos", fake_list)
    resp = client.post("/api/org-scan", json={"org": "nobody-here"})
    assert resp.status_code == 400
    assert "nobody-here" in resp.json()["detail"]


def test_org_scan_stream_emits_discover_and_repo_progress(tmp_path, client, monkeypatch):
    repo = tmp_path / "repo-a"
    _init_repo(repo)
    (repo / "a.txt").write_text("hi\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "init")

    monkeypatch.setattr(
        webapp, "_list_github_repos",
        lambda login, token: [{"clone_url": str(repo), "full_name": "some-org/repo-a"}],
    )

    resp = client.post("/api/org-scan/stream", json={"org": "some-org"})
    assert resp.status_code == 200
    events = _collect_sse(resp)

    assert events[-1][0] == "done"
    assert events[-1][1]["total_repos"] == 1

    discover_events = [d for e, d in events if e == "progress" and d.get("step") == "discover"]
    assert any(d.get("done") and d.get("repos") for d in discover_events)

    repo_events = [d for e, d in events if e == "progress" and d.get("step") == "repo"]
    assert any(d.get("done") for d in repo_events)


def test_org_scan_stream_repo_finished_event_carries_full_report(tmp_path, client, monkeypatch):
    dirty_repo = tmp_path / "dirty-repo"
    _init_repo(dirty_repo)
    (dirty_repo / "assets").mkdir()
    (dirty_repo / "assets" / "icon.woff2").write_bytes(b"function evil(){require('fs')}")
    _git(dirty_repo, "add", ".")
    _git(dirty_repo, "commit", "-q", "-m", "add masquerade")

    monkeypatch.setattr(
        webapp, "_list_github_repos",
        lambda login, token: [{"clone_url": str(dirty_repo), "full_name": "some-org/dirty-repo"}],
    )

    resp = client.post("/api/org-scan/stream", json={"org": "some-org"})
    events = _collect_sse(resp)

    finished = [d for e, d in events if e == "progress" and d.get("step") == "repo" and d.get("done") and not d.get("error")]
    assert len(finished) == 1
    report = finished[0]["report"]
    assert report["summary"]["total_findings"] == 1
    assert report["repo_name"] == "some-org/dirty-repo"
