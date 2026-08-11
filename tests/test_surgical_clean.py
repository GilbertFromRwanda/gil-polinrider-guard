import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

git_filter_repo = pytest.importorskip("git_filter_repo")
import surgical_clean  # noqa: E402


def _git(repo, *args):
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


def _make_repo_with_buried_payload(tmp_path) -> Path:
    origin = tmp_path / "origin"
    origin.mkdir()
    _git(origin, "init", "-q")
    _git(origin, "config", "user.email", "t@example.com")
    _git(origin, "config", "user.name", "T")

    (origin / "app.js").write_text('console.log("hello");\n')
    _git(origin, "add", "app.js")
    _git(origin, "commit", "-q", "-m", "legit commit 1")

    (origin / "app.js").write_text(
        'console.log("hello");\n'
        'global["_V"]="8-st*";\n'
        'fetch("https://trongrid.io/x");\n'
    )
    _git(origin, "add", "app.js")
    _git(origin, "commit", "-q", "-m", "malicious injection")

    (origin / "app.js").write_text(
        'console.log("hello");\n'
        'global["_V"]="8-st*";\n'
        'fetch("https://trongrid.io/x");\n'
        'console.log("feature added");\n'
    )
    _git(origin, "add", "app.js")
    _git(origin, "commit", "-q", "-m", "legit commit on top")

    mirror = tmp_path / "mirror.git"
    subprocess.run(
        ["git", "clone", "-q", "--mirror", str(origin), str(mirror)],
        check=True, capture_output=True,
    )
    return mirror


def test_analyze_finds_ioc_without_modifying_repo(tmp_path):
    mirror = _make_repo_with_buried_payload(tmp_path)
    patterns = surgical_clean.load_patterns(None)

    findings = surgical_clean.analyze(mirror, patterns)
    assert len(findings) == 4  # 2 IOC lines x 2 blobs (malicious commit + commit on top)

    # unmodified: re-analyzing gives the identical result
    findings_again = surgical_clean.analyze(mirror, patterns)
    assert findings == findings_again


def test_apply_strips_payload_and_preserves_legit_content(tmp_path):
    mirror = _make_repo_with_buried_payload(tmp_path)
    patterns = surgical_clean.load_patterns(None)

    surgical_clean.apply_clean(mirror, patterns, force_non_mirror=False)

    remaining = surgical_clean.analyze(mirror, patterns)
    assert remaining == []

    log = subprocess.run(
        ["git", "log", "--oneline", "--all"], cwd=mirror, capture_output=True, text=True, check=True
    )
    # The malicious-only commit becomes empty once its lines are stripped
    # and git filter-repo prunes it; only the two legitimate commits remain.
    assert "malicious injection" not in log.stdout
    assert "legit commit 1" in log.stdout
    assert "legit commit on top" in log.stdout

    tip = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=mirror, capture_output=True, text=True, check=True
    ).stdout.strip()
    content = subprocess.run(
        ["git", "show", f"{tip}:app.js"], cwd=mirror, capture_output=True, text=True, check=True
    ).stdout
    assert "hello" in content
    assert "feature added" in content
    assert "trongrid.io" not in content
    assert "_V" not in content


def test_apply_refuses_non_mirror_by_default(tmp_path):
    mirror = _make_repo_with_buried_payload(tmp_path)
    working_copy = tmp_path / "working"
    subprocess.run(["git", "clone", "-q", str(mirror), str(working_copy)], check=True, capture_output=True)

    patterns = surgical_clean.load_patterns(None)
    with pytest.raises(RuntimeError, match="bare/mirror clone"):
        surgical_clean.apply_clean(working_copy, patterns, force_non_mirror=False)
