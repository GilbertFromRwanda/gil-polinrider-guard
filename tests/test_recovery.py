import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

pytest.importorskip("git_filter_repo")

from polinrider_guard import recovery  # noqa: E402


def _git(repo, *args):
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


def _init_repo(repo):
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test User")


def _mirror(tmp_path, src: Path) -> Path:
    mirror = tmp_path / "mirror.git"
    subprocess.run(
        ["git", "clone", "-q", "--mirror", str(src), str(mirror)],
        check=True, capture_output=True,
    )
    return mirror


def test_find_masquerade_blobs_finds_confirmed_js_disguised_as_font(tmp_path):
    repo = tmp_path / "repo"
    _init_repo(repo)
    (repo / "assets").mkdir()
    (repo / "assets" / "icon.woff2").write_bytes(b"function evil(){require('fs')}")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "add icon")

    mirror = _mirror(tmp_path, repo)
    findings = recovery.find_masquerade_blobs(mirror)
    assert len(findings) == 1
    sha, path = findings[0]
    assert path == "assets/icon.woff2"


def test_find_masquerade_blobs_excludes_weak_tier(tmp_path):
    # Magic bytes mismatch but no JS keywords -- scan_masquerade.py itself
    # would only call this "medium", not "critical", so it must not be a
    # candidate for auto-blanking.
    repo = tmp_path / "repo"
    _init_repo(repo)
    (repo / "assets").mkdir()
    (repo / "assets" / "weird.woff2").write_bytes(b"\x01\x02\x03not a real font header at all, just noise")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "add weird font")

    mirror = _mirror(tmp_path, repo)
    assert recovery.find_masquerade_blobs(mirror) == []


def test_find_masquerade_blobs_ignores_legitimate_font(tmp_path):
    repo = tmp_path / "repo"
    _init_repo(repo)
    (repo / "assets").mkdir()
    (repo / "assets" / "icon.woff2").write_bytes(b"wOF2" + b"\x00" * 32)
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "add real font")

    mirror = _mirror(tmp_path, repo)
    assert recovery.find_masquerade_blobs(mirror) == []


def test_apply_clean_truncates_padding_line_preserving_legit_prefix(tmp_path):
    # A payload hidden after 80+ spaces on the SAME line as real code (e.g.
    # `export default createJestConfig(config);<...80 spaces...>evil()`)
    # must only lose the hidden suffix -- dropping the whole line would
    # delete the legitimate statement too and break the file.
    repo = tmp_path / "repo"
    _init_repo(repo)
    legit = "export default createJestConfig(config);"
    hidden = "require('fs').readFileSync('/etc/passwd')"
    padded_line = legit + (" " * 90) + hidden
    (repo / "jest.config.js").write_text(padded_line + "\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "add jest config with hidden payload")

    mirror = _mirror(tmp_path, repo)
    patterns = recovery.load_patterns()

    recovery.apply_clean(mirror, patterns, force_non_mirror=False)

    tip = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=mirror, capture_output=True, text=True, check=True
    ).stdout.strip()
    content = subprocess.run(
        ["git", "show", f"{tip}:jest.config.js"], cwd=mirror, capture_output=True, text=True, check=True
    ).stdout
    assert legit in content
    assert hidden not in content


def test_apply_clean_truncates_padding_line_even_when_hidden_suffix_is_also_an_ioc_match(tmp_path):
    # The hidden payload after the padding commonly matches an IOC pattern
    # too (e.g. eval(Buffer.from(...))) -- the IOC check must not run
    # against the untruncated line, or it drops the whole line (legitimate
    # closing brace included) instead of just the hidden suffix.
    repo = tmp_path / "repo"
    _init_repo(repo)
    legit = "};"
    hidden = "eval(Buffer.from('bWFsaWNpb3Vz','base64').toString())"
    padded_line = legit + (" " * 90) + hidden
    (repo / "postcss.config.js").write_text(
        'module.exports = {\n  plugins: {\n    "@tailwindcss/postcss": {},\n    autoprefixer: {},\n  },\n'
        + padded_line + "\n"
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "add postcss config with hidden payload")

    mirror = _mirror(tmp_path, repo)
    patterns = recovery.load_patterns()

    recovery.apply_clean(mirror, patterns, force_non_mirror=False)

    tip = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=mirror, capture_output=True, text=True, check=True
    ).stdout.strip()
    content = subprocess.run(
        ["git", "show", f"{tip}:postcss.config.js"], cwd=mirror, capture_output=True, text=True, check=True
    ).stdout
    assert legit in content
    assert "eval(Buffer.from(" not in content
    assert "autoprefixer" in content


def test_blob_paths_maps_every_historical_blob_to_its_paths(tmp_path):
    repo = tmp_path / "repo"
    _init_repo(repo)
    (repo / "a.js").write_text("one\n")
    (repo / "b.js").write_text("two\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "add a and b")

    mirror = _mirror(tmp_path, repo)
    path_map = recovery.blob_paths(mirror)
    paths_seen = {p for paths in path_map.values() for p in paths}
    assert paths_seen == {"a.js", "b.js"}


def test_apply_clean_excluded_blob_shas_scopes_rewrite_away_from_unchecked_files(tmp_path):
    # "Checked files only": a user can uncheck a file in the analyze preview
    # (e.g. a false positive) and have the rewrite leave every blob ever
    # committed at that path completely untouched, even though it still
    # matches an IOC pattern. The excluded set (not an included one) is
    # what gets passed -- see build_callback_source()'s docstring for why
    # that matters at real repo scale.
    repo = tmp_path / "repo"
    _init_repo(repo)
    (repo / "keep.js").write_text('console.log("safe");\nglobal["_V"]="8-st*";\n')
    (repo / "skip.js").write_text('console.log("also safe");\nglobal["_V"]="8-st*";\n')
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "add both files")

    mirror = _mirror(tmp_path, repo)
    patterns = recovery.load_patterns()

    path_map = recovery.blob_paths(mirror)
    excluded = {sha for sha, paths in path_map.items() if "skip.js" in paths}
    assert excluded

    recovery.apply_clean(mirror, patterns, excluded_blob_shas=excluded, force_non_mirror=False)

    tip = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=mirror, capture_output=True, text=True, check=True
    ).stdout.strip()
    keep_content = subprocess.run(
        ["git", "show", f"{tip}:keep.js"], cwd=mirror, capture_output=True, text=True, check=True
    ).stdout
    skip_content = subprocess.run(
        ["git", "show", f"{tip}:skip.js"], cwd=mirror, capture_output=True, text=True, check=True
    ).stdout

    assert "_V" not in keep_content
    assert "_V" in skip_content


def test_apply_clean_blanks_confirmed_masquerade_blob(tmp_path):
    repo = tmp_path / "repo"
    _init_repo(repo)
    (repo / "assets").mkdir()
    (repo / "assets" / "icon.woff2").write_bytes(b"function evil(){require('fs')}")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "add icon")
    (repo / "readme.txt").write_text("unrelated legitimate file\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "add readme")

    mirror = _mirror(tmp_path, repo)
    patterns = recovery.load_patterns()
    masquerade_blobs = recovery.find_masquerade_blobs(mirror)
    masquerade_shas = [sha for sha, _ in masquerade_blobs]
    assert len(masquerade_shas) == 1

    recovery.apply_clean(mirror, patterns, masquerade_shas=masquerade_shas, force_non_mirror=False)

    assert recovery.find_masquerade_blobs(mirror) == []

    checkout = tmp_path / "checkout"
    subprocess.run(["git", "clone", "-q", str(mirror), str(checkout)], check=True, capture_output=True)
    assert (checkout / "assets" / "icon.woff2").read_bytes() == b""
    assert "unrelated legitimate file" in (checkout / "readme.txt").read_text()


def test_find_risky_vscode_tasks_reports_current_tree(tmp_path):
    repo = tmp_path / "repo"
    _init_repo(repo)
    vscode_dir = repo / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "tasks.json").write_text(
        '{"tasks": [{"label": "format-check", "command": "node", "args": ["a.woff2"],'
        ' "runOptions": {"runOn": "folderOpen"}, "hide": true}]}\n'
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "add tasks.json")

    findings = recovery.find_risky_vscode_tasks(repo)
    assert len(findings) == 1
    assert findings[0].task_label == "format-check"


def test_find_risky_vscode_tasks_clean_repo(tmp_path):
    repo = tmp_path / "repo"
    _init_repo(repo)
    (repo / "a.txt").write_text("hello\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "add file")

    assert recovery.find_risky_vscode_tasks(repo) == []


def test_remove_risky_vscode_tasks_keeps_legit_tasks(tmp_path):
    repo = tmp_path / "repo"
    _init_repo(repo)
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

    edited = recovery.remove_risky_vscode_tasks(repo)
    assert edited == [str(Path(".vscode") / "tasks.json")]

    assert recovery.find_risky_vscode_tasks(repo) == []
    data = json.loads((vscode_dir / "tasks.json").read_text())
    labels = [t["label"] for t in data["tasks"]]
    assert labels == ["legit-build"]


def test_remove_risky_vscode_tasks_handles_shell_string_command_and_extra_keys(tmp_path):
    # Matches the shape of a real captured sample: a single shell-string
    # `command` (not command+args), plus an unrelated top-level
    # "configurations" block (launch.json content bleeding into tasks.json)
    # that must survive untouched.
    repo = tmp_path / "repo"
    _init_repo(repo)
    vscode_dir = repo / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "tasks.json").write_text(
        """{
  "version": "2.0.0",
  "configurations": [
    {"type": "node", "request": "launch", "name": "Run My Project"}
  ],
  "tasks": [
    {
      "label": "eslint-check",
      "type": "shell",
      "command": "(command -v node >/dev/null 2>&1 && node ./assetsdir/iconfile.woff2) || echo ''",
      "hide": true,
      "presentation": {"reveal": "never", "echo": false},
      "runOptions": {"runOn": "folderOpen"}
    },
  ]
}
"""
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "add real-shaped tasks.json")

    found = recovery.find_risky_vscode_tasks(repo)
    assert len(found) == 1

    edited = recovery.remove_risky_vscode_tasks(repo)
    assert edited == [str(Path(".vscode") / "tasks.json")]

    data = json.loads((vscode_dir / "tasks.json").read_text())
    assert data["tasks"] == []
    assert data["configurations"][0]["name"] == "Run My Project"
    assert recovery.find_risky_vscode_tasks(repo) == []


def test_remove_risky_vscode_tasks_no_findings_leaves_file_untouched(tmp_path):
    repo = tmp_path / "repo"
    _init_repo(repo)
    vscode_dir = repo / ".vscode"
    vscode_dir.mkdir()
    original = '{"tasks": [{"label": "legit-build", "command": "npm", "args": ["run", "build"]}]}\n'
    (vscode_dir / "tasks.json").write_text(original)
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "add clean tasks.json")

    assert recovery.remove_risky_vscode_tasks(repo) == []
    assert (vscode_dir / "tasks.json").read_text() == original


def test_find_risky_vscode_task_blobs_finds_old_but_not_current(tmp_path):
    # The risky tasks.json was committed once, then fixed in a later commit
    # -- the current tree is clean, but the old blob is still recoverable
    # from history (checking out the first commit, a stale clone, etc.).
    repo = tmp_path / "repo"
    _init_repo(repo)
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
    _git(repo, "commit", "-q", "-m", "fix tasks.json")

    mirror = _mirror(tmp_path, repo)
    found = recovery.find_risky_vscode_task_blobs(mirror)
    assert len(found) == 1
    assert found[0][1] == ".vscode/tasks.json"

    # Current-tree-only detection agrees the tip is already clean.
    assert recovery.find_risky_vscode_tasks(repo) == []


def test_find_risky_vscode_task_blobs_empty_on_clean_history(tmp_path):
    repo = tmp_path / "repo"
    _init_repo(repo)
    vscode_dir = repo / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "tasks.json").write_text(
        '{"tasks": [{"label": "legit-build", "command": "npm", "args": ["run", "build"]}]}\n'
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "add clean tasks.json")

    mirror = _mirror(tmp_path, repo)
    assert recovery.find_risky_vscode_task_blobs(mirror) == []


def test_find_risky_vscode_task_blobs_ignores_node_modules(tmp_path):
    repo = tmp_path / "repo"
    _init_repo(repo)
    nested = repo / "vendor" / "node_modules" / "some-pkg" / ".vscode"
    nested.mkdir(parents=True)
    (nested / "tasks.json").write_text(
        '{"tasks": [{"label": "format-check", "command": "node", "args": ["a.woff2"],'
        ' "runOptions": {"runOn": "folderOpen"}, "hide": true}]}\n'
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "add vendored tasks.json under node_modules")

    mirror = _mirror(tmp_path, repo)
    assert recovery.find_risky_vscode_task_blobs(mirror) == []


def test_apply_clean_blanks_historical_risky_tasks_json_blob(tmp_path):
    repo = tmp_path / "repo"
    _init_repo(repo)
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
    _git(repo, "commit", "-q", "-m", "fix tasks.json")

    mirror = _mirror(tmp_path, repo)
    patterns = recovery.load_patterns()
    vscode_task_blobs = recovery.find_risky_vscode_task_blobs(mirror)
    vscode_task_shas = [sha for sha, _ in vscode_task_blobs]
    assert len(vscode_task_shas) == 1

    recovery.apply_clean(mirror, patterns, vscode_task_shas=vscode_task_shas, force_non_mirror=False)

    assert recovery.find_risky_vscode_task_blobs(mirror) == []

    checkout = tmp_path / "checkout"
    subprocess.run(["git", "clone", "-q", str(mirror), str(checkout)], check=True, capture_output=True)
    first_commit = subprocess.run(
        ["git", "log", "--reverse", "--format=%H"], cwd=checkout, capture_output=True, text=True, check=True
    ).stdout.splitlines()[0]
    old_content = subprocess.run(
        ["git", "show", f"{first_commit}:.vscode/tasks.json"], cwd=checkout, capture_output=True, text=True, check=True
    ).stdout
    assert old_content == ""

    # The fix commit's own content is untouched.
    data = json.loads((checkout / ".vscode" / "tasks.json").read_text())
    assert data["tasks"][0]["label"] == "legit-build"
