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


@pytest.fixture(autouse=True)
def _cleanup_kept_clones():
    # Org scans now keep each successfully-scanned repo's clone on disk
    # (see KEPT_CLONE_PREFIX) instead of discarding it -- sweep up whatever
    # a test left behind so repeated runs don't pile up temp dirs.
    yield
    for clone in webapp._list_kept_clones():
        webapp._rmtree_force(Path(clone["path"]))


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


def test_list_github_repos_uses_authenticated_endpoint_for_own_account(monkeypatch):
    """/users/{login}/repos only ever serves public repos, so scanning the
    account a token belongs to has to go through /user/repos instead."""
    calls = []

    def fake_get(path, token):
        calls.append(path)
        assert token == "tok"
        if path == "/user":
            return {"login": "Me"}
        if path.startswith("/orgs/"):
            raise urllib.error.HTTPError(path, 404, "Not Found", {}, None)
        if path.startswith("/user/repos"):
            return [{"clone_url": "https://example.invalid/p.git", "full_name": "me/private", "private": True}]
        raise AssertionError(f"should not fall back to the public endpoint: {path}")

    monkeypatch.setattr(webapp, "_github_api_get", fake_get)
    repos = webapp._list_github_repos("me", "tok")

    assert [r["full_name"] for r in repos] == ["me/private"]
    listing = next(c for c in calls if c.startswith("/user/repos"))
    assert "visibility=all" in listing
    assert "affiliation=owner" in listing


def test_list_github_repos_keeps_public_endpoint_for_another_users_account(monkeypatch):
    """A token can't enumerate someone else's private repos, so a login that
    isn't the token's own account still uses the public endpoint."""
    calls = []

    def fake_get(path, token):
        calls.append(path)
        if path == "/user":
            return {"login": "me"}
        if path.startswith("/orgs/"):
            raise urllib.error.HTTPError(path, 404, "Not Found", {}, None)
        assert path.startswith("/users/someone-else/repos")
        return [{"clone_url": "https://example.invalid/a.git", "full_name": "someone-else/a"}]

    monkeypatch.setattr(webapp, "_github_api_get", fake_get)
    repos = webapp._list_github_repos("someone-else", "tok")

    assert [r["full_name"] for r in repos] == ["someone-else/a"]
    assert not any(c.startswith("/user/repos") for c in calls)


def test_list_github_repos_org_listing_asks_for_all_types(monkeypatch):
    """An org's private repos come back from /orgs/{org}/repos when the token
    can read them -- assert we don't narrow it to public."""
    calls = []

    def fake_get(path, token):
        calls.append(path)
        if path == "/user":
            return {"login": "me"}
        return [{"clone_url": "https://example.invalid/a.git", "full_name": "some-org/a", "private": True}]

    monkeypatch.setattr(webapp, "_github_api_get", fake_get)
    repos = webapp._list_github_repos("some-org", "tok")

    assert [r["full_name"] for r in repos] == ["some-org/a"]
    assert "type=all" in calls[-1]
    assert "type=public" not in calls[-1]


def test_list_github_repos_falls_back_to_public_when_own_listing_is_empty(monkeypatch):
    """A fine-grained token scoped to an org only makes /user/repos empty; a
    public-only list beats reporting the account as having no repos."""

    def fake_get(path, token):
        if path == "/user":
            return {"login": "me"}
        if path.startswith("/orgs/"):
            raise urllib.error.HTTPError(path, 404, "Not Found", {}, None)
        if path.startswith("/user/repos"):
            return []
        return [{"clone_url": "https://example.invalid/a.git", "full_name": "me/a"}]

    monkeypatch.setattr(webapp, "_github_api_get", fake_get)
    assert [r["full_name"] for r in webapp._list_github_repos("me", "tok")] == ["me/a"]


def test_list_github_repos_empty_org_reports_zero_rather_than_404(monkeypatch):
    def fake_get(path, token):
        assert path.startswith("/orgs/")
        return []

    monkeypatch.setattr(webapp, "_github_api_get", fake_get)
    assert webapp._list_github_repos("empty-org", None) == []


def test_github_token_login_returns_none_on_rejected_token(monkeypatch):
    """A bad token must not crash discovery here -- the repos call that
    follows raises the 401 that actually tells the user what's wrong."""

    def fake_get(path, token):
        raise urllib.error.HTTPError(path, 401, "Bad credentials", {}, None)

    monkeypatch.setattr(webapp, "_github_api_get", fake_get)
    assert webapp._github_token_login("nope") is None


def test_list_github_repos_without_token_never_calls_user_endpoint(monkeypatch):
    calls = []

    def fake_get(path, token):
        calls.append(path)
        if path.startswith("/orgs/"):
            raise urllib.error.HTTPError(path, 404, "Not Found", {}, None)
        return [{"clone_url": "https://example.invalid/a.git", "full_name": "me/a"}]

    monkeypatch.setattr(webapp, "_github_api_get", fake_get)
    webapp._list_github_repos("me", None)
    assert "/user" not in calls
    assert not any(c.startswith("/user/repos") for c in calls)


def test_paginate_github_repos_walks_pages_and_caps(monkeypatch):
    pages = {1: [{"n": i} for i in range(100)], 2: [{"n": 100}]}

    def fake_get(path, token):
        page = int(path.rsplit("page=", 1)[1])
        return pages.get(page, [])

    monkeypatch.setattr(webapp, "_github_api_get", fake_get)
    repos = webapp._paginate_github_repos("/users/x/repos?per_page=100", None)
    assert len(repos) == 101


# --- /api/org-scan --------------------------------------------------------------


def test_org_scan_clones_scans_and_keeps_each_repo(tmp_path, client, monkeypatch):
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

    # Unlike a failed/timed-out clone, a successfully scanned repo's clone
    # is kept on disk (see KEPT_CLONE_PREFIX) rather than discarded, so
    # Recovery/the file viewer/"Open in folder" have something to point at
    # until the user deletes it via the "Temp clones" panel.
    for r in data["repos"]:
        assert r["source_url"] in (str(clean_repo), str(dirty_repo))
        source_path = Path(r["source_path"])
        assert source_path.name.startswith(webapp.KEPT_CLONE_PREFIX)
        assert (source_path / webapp.KEPT_CLONE_META_FILENAME).exists()
        assert r["clone_id"] == source_path.name


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


def test_org_scan_discards_clone_on_clone_failure(client, monkeypatch):
    monkeypatch.setattr(
        webapp, "_list_github_repos",
        lambda login, token: [{"clone_url": "https://example.invalid/does-not-exist.git", "full_name": "some-org/nope"}],
    )

    resp = client.post("/api/org-scan", json={"org": "some-org"})
    assert resp.status_code == 200
    assert resp.json()["repos"] == []
    assert webapp._list_kept_clones() == []


# --- /api/temp-clones ------------------------------------------------------


def _run_one_org_scan(client, monkeypatch, repo_path, full_name):
    monkeypatch.setattr(
        webapp, "_list_github_repos",
        lambda login, token: [{"clone_url": str(repo_path), "full_name": full_name}],
    )
    resp = client.post("/api/org-scan", json={"org": "some-org"})
    assert resp.status_code == 200
    return resp.json()["repos"][0]


def test_list_temp_clones_returns_kept_clones(tmp_path, client, monkeypatch):
    repo = tmp_path / "repo-a"
    _init_repo(repo)
    (repo / "a.txt").write_text("hi\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "init")

    scanned = _run_one_org_scan(client, monkeypatch, repo, "some-org/repo-a")

    resp = client.get("/api/temp-clones")
    assert resp.status_code == 200
    clones = resp.json()["clones"]
    assert len(clones) == 1
    assert clones[0]["path"] == scanned["source_path"]
    assert clones[0]["repo_name"] == "some-org/repo-a"
    assert clones[0]["clone_url"] == str(repo)
    assert clones[0]["size_bytes"] > 0


def test_delete_one_temp_clone(tmp_path, client, monkeypatch):
    repo = tmp_path / "repo-a"
    _init_repo(repo)
    (repo / "a.txt").write_text("hi\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "init")

    scanned = _run_one_org_scan(client, monkeypatch, repo, "some-org/repo-a")
    clone_id = Path(scanned["source_path"]).name

    resp = client.delete(f"/api/temp-clones/{clone_id}")
    assert resp.status_code == 200
    assert resp.json()["deleted"] == [clone_id]
    assert not Path(scanned["source_path"]).exists()
    assert webapp._list_kept_clones() == []


def test_delete_temp_clone_rejects_path_traversal(client):
    resp = client.delete("/api/temp-clones/..%2F..%2Fetc")
    assert resp.status_code in (400, 404)


def test_delete_temp_clone_404s_for_unknown_id(client):
    resp = client.delete(f"/api/temp-clones/{webapp.KEPT_CLONE_PREFIX}doesnotexist")
    assert resp.status_code == 404


def test_delete_all_temp_clones(tmp_path, client, monkeypatch):
    repo_a = tmp_path / "repo-a"
    _init_repo(repo_a)
    (repo_a / "a.txt").write_text("hi\n")
    _git(repo_a, "add", ".")
    _git(repo_a, "commit", "-q", "-m", "init")

    repo_b = tmp_path / "repo-b"
    _init_repo(repo_b)
    (repo_b / "b.txt").write_text("hi\n")
    _git(repo_b, "add", ".")
    _git(repo_b, "commit", "-q", "-m", "init")

    monkeypatch.setattr(
        webapp, "_list_github_repos",
        lambda login, token: [
            {"clone_url": str(repo_a), "full_name": "some-org/repo-a"},
            {"clone_url": str(repo_b), "full_name": "some-org/repo-b"},
        ],
    )
    resp = client.post("/api/org-scan", json={"org": "some-org"})
    assert resp.status_code == 200
    assert len(webapp._list_kept_clones()) == 2

    resp = client.delete("/api/temp-clones")
    assert resp.status_code == 200
    assert len(resp.json()["deleted"]) == 2
    assert webapp._list_kept_clones() == []


# --- /api/scan keep_clone (org-repo Retry) ----------------------------------
# Regression coverage for: retrying a failed repo in an org scan goes through
# /api/scan/stream (see attachRetryButton in index.html), which -- before
# ScanRequest.keep_clone existed -- always used _last_scan_clone, the single
# top-level scan's one slot. Any other scan (or another retry) starting
# afterward would silently delete that slot's directory, so a user who'd
# retried an org repo and then, say, ran an unrelated single-URL scan would
# hit "path does not exist" clicking Recovery's "Check what would be
# cleaned" on the retried repo -- even though they never touched it.


def test_scan_with_keep_clone_uses_tracked_prefix_not_last_scan_clone(tmp_path, client):
    # Goes straight through _run_scan rather than /api/scan, same as
    # test_webapp_recovery.py's analogous clone-persistence tests --
    # /api/scan's _validate_request requires a real git URL scheme
    # (http(s)/git/ssh), which a local source path isn't, and _run_scan
    # itself doesn't care what scheme the "url" arg has.
    repo = tmp_path / "repo-a"
    _init_repo(repo)
    (repo / "a.txt").write_text("hi\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "init")

    webapp._last_scan_clone = None
    source_path = None
    try:
        events = list(
            webapp._run_scan(str(repo), None, None, None, keep_clone=True, repo_name="some-org/repo-a")
        )
        done = [data for event, data in events if event == "done"]
        assert len(done) == 1
        report = done[0]
        assert report["repo_name"] == "some-org/repo-a"
        source_path = Path(report["source_path"])
        assert source_path.name.startswith(webapp.KEPT_CLONE_PREFIX)
        assert (source_path / webapp.KEPT_CLONE_META_FILENAME).exists()
        assert report["clone_id"] == source_path.name
        # keep_clone must never touch the single top-level scan's slot --
        # a retry has nothing to do with "New scan".
        assert webapp._last_scan_clone is None
    finally:
        if source_path is not None and source_path.exists():
            webapp._rmtree_force(source_path)
        if webapp._last_scan_clone is not None and webapp._last_scan_clone.exists():
            webapp._rmtree_force(webapp._last_scan_clone)
        webapp._last_scan_clone = None


def test_unrelated_single_scan_does_not_delete_a_kept_clone_retry(tmp_path, client):
    retried_repo = tmp_path / "retried-repo"
    _init_repo(retried_repo)
    (retried_repo / "a.txt").write_text("hi\n")
    _git(retried_repo, "add", ".")
    _git(retried_repo, "commit", "-q", "-m", "init")

    other_repo = tmp_path / "other-repo"
    _init_repo(other_repo)
    (other_repo / "b.txt").write_text("hi\n")
    _git(other_repo, "add", ".")
    _git(other_repo, "commit", "-q", "-m", "init")

    webapp._last_scan_clone = None
    retried_source_path = None
    try:
        events = list(
            webapp._run_scan(
                str(retried_repo), None, None, None, keep_clone=True, repo_name="some-org/retried-repo"
            )
        )
        done = [data for event, data in events if event == "done"]
        retried_source_path = Path(done[0]["source_path"])
        assert retried_source_path.exists()

        # An unrelated single-URL scan (keep_clone unset, like "New scan"
        # actually sends) -- this is what /api/scan's own _last_scan_clone
        # logic runs on entry, real scheme validation and all.
        resp = client.post("/api/scan", json={"url": "https://example.invalid/other-repo.git"})
        assert resp.status_code == 400  # example.invalid isn't cloneable -- irrelevant here

        # The unrelated single-URL scan must not have deleted the retried
        # org repo's clone -- this is the exact bug: Recovery's "Check
        # what would be cleaned" failing with "path does not exist" for a
        # repo the user never re-scanned.
        assert retried_source_path.exists()
        resp = client.post("/api/recover/analyze", json={"path": str(retried_source_path)})
        assert resp.status_code == 200
    finally:
        if retried_source_path is not None and retried_source_path.exists():
            webapp._rmtree_force(retried_source_path)
        if webapp._last_scan_clone is not None and webapp._last_scan_clone.exists():
            webapp._rmtree_force(webapp._last_scan_clone)
        webapp._last_scan_clone = None
