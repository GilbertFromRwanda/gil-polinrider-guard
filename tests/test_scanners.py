import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CLEAN = ROOT / "examples" / "clean-project"
VULNERABLE = ROOT / "examples" / "vulnerable-samples"

sys.path.insert(0, str(ROOT))

from polinrider_guard import guard, scan_git_dates, scan_ioc, scan_masquerade, scan_unicode, scan_vscode  # noqa: E402


def test_unicode_scanner_clean():
    assert scan_unicode.scan_path(CLEAN) == []


def test_unicode_scanner_finds_glassworm_pattern():
    findings = scan_unicode.scan_path(VULNERABLE)
    codepoints = {f.codepoint for f in findings}
    assert "U+200B" in codepoints
    assert "U+FE00" in codepoints
    assert any(f.file.endswith("app.js") for f in findings)


def test_masquerade_scanner_clean():
    assert scan_masquerade.scan_path(CLEAN) == []


def test_masquerade_scanner_finds_font_vector():
    findings = scan_masquerade.scan_path(VULNERABLE)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.claimed_extension == ".png"
    assert finding.actual_type == "text/javascript"
    assert finding.severity == "critical"


def test_vscode_scanner_clean():
    assert scan_vscode.scan_path(CLEAN) == []


def test_vscode_scanner_finds_tasksjacker_pattern():
    findings = scan_vscode.scan_path(VULNERABLE)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.task_label == "format-check"
    assert finding.severity == "critical"
    assert any("folderOpen" in r for r in finding.reasons)
    assert any("hide=true" in r for r in finding.reasons)


def test_ioc_scanner_clean():
    assert scan_ioc.scan_path(CLEAN) == []


def test_ioc_scanner_self_scan_is_clean():
    # iocs.py necessarily contains these patterns as literal data (it's the
    # pattern definitions module) -- it must not flag itself, the same way
    # an antivirus engine doesn't flag its own signature database.
    assert scan_ioc.scan_path(ROOT / "polinrider_guard") == []


def test_ioc_scanner_respects_ignore_marker(tmp_path):
    (tmp_path / "sample.js").write_text(
        'const c2 = "trongrid.io"; // polinrider-guard:ignore\n'
    )
    assert scan_ioc.scan_path(tmp_path) == []


def test_ioc_scanner_finds_c2_domain():
    findings = scan_ioc.scan_path(VULNERABLE)
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert "trongrid.io" in findings[0].matched_text
    assert findings[0].file.endswith("analytics.js")


def test_guard_exit_code_clean(tmp_path):
    report = guard.run_guard(CLEAN, include_git=False)
    assert report["summary"]["total_findings"] == 0


def test_guard_exit_code_vulnerable():
    report = guard.run_guard(VULNERABLE, include_git=False)
    assert report["summary"]["total_findings"] > 0
    assert report["summary"]["by_severity"].get("critical", 0) >= 2


def test_cli_clean_project_exits_zero():
    result = subprocess.run(
        [sys.executable, "-m", "polinrider_guard.guard", str(CLEAN), "--no-git"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "No findings" in result.stdout


def test_cli_vulnerable_samples_exits_one():
    result = subprocess.run(
        [sys.executable, "-m", "polinrider_guard.guard", str(VULNERABLE), "--no-git"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "Total findings" in result.stdout


def test_git_date_scanner_flags_backdated_commit(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    def run(*args):
        subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)

    run("init", "-q")
    run("config", "user.email", "test@example.com")
    run("config", "user.name", "Test User")

    (repo / "a.txt").write_text("first\n")
    run("add", "a.txt")
    run("commit", "-q", "-m", "normal commit")

    # Simulate ForceMemo-style backdating: author date 90 days in the past,
    # committer date effectively now (the default when GIT_COMMITTER_DATE
    # is left unset).
    (repo / "b.txt").write_text("second\n")
    run("add", "b.txt")
    subprocess.run(
        ["git", "commit", "-q", "-m", "backdated commit", "--date=90 days ago"],
        cwd=repo,
        check=True,
        capture_output=True,
    )

    findings = scan_git_dates.scan_path(repo, threshold_seconds=3600)
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].subject == "backdated commit"


def test_git_date_scanner_no_findings_on_normal_history(tmp_path):
    repo = tmp_path / "repo2"
    repo.mkdir()

    def run(*args):
        subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)

    run("init", "-q")
    run("config", "user.email", "test@example.com")
    run("config", "user.name", "Test User")

    (repo / "a.txt").write_text("first\n")
    run("add", "a.txt")
    run("commit", "-q", "-m", "normal commit 1")

    (repo / "b.txt").write_text("second\n")
    run("add", "b.txt")
    run("commit", "-q", "-m", "normal commit 2")

    findings = scan_git_dates.scan_path(repo, threshold_seconds=3600)
    assert findings == []


def test_git_date_scanner_raises_on_non_repo(tmp_path):
    with pytest.raises(scan_git_dates.NotAGitRepoError):
        scan_git_dates.scan_path(tmp_path)
