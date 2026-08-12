import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from polinrider_guard import allowlist  # noqa: E402


def test_load_allowlist_missing_file_returns_empty(tmp_path):
    assert allowlist.load_allowlist(tmp_path) == []


def test_load_allowlist_parses_entries_and_skips_comments_and_blanks(tmp_path):
    (tmp_path / allowlist.ALLOWLIST_FILENAME).write_text(
        "# comment line\n"
        "\n"
        "extension_masquerade | assets/font.woff2 | vendored, verified upstream\n"
        "vscode_tasks|.vscode/tasks.json\n",
        encoding="utf-8",
    )
    entries = allowlist.load_allowlist(tmp_path)
    assert entries == [
        allowlist.AllowlistEntry("extension_masquerade", "assets/font.woff2", "vendored, verified upstream"),
        allowlist.AllowlistEntry("vscode_tasks", ".vscode/tasks.json", ""),
    ]


def test_load_allowlist_skips_malformed_lines(tmp_path):
    (tmp_path / allowlist.ALLOWLIST_FILENAME).write_text(
        "no_pipe_here_at_all\n"
        "|missing_scanner\n"
        "scanner_only|\n"
        "good_scanner|good_id|reason\n",
        encoding="utf-8",
    )
    entries = allowlist.load_allowlist(tmp_path)
    assert entries == [allowlist.AllowlistEntry("good_scanner", "good_id", "reason")]


def test_is_file_allowlisted_matches_scanner_and_file():
    entries = [allowlist.AllowlistEntry("extension_masquerade", "a.woff2", "")]
    assert allowlist.is_file_allowlisted(entries, "extension_masquerade", "a.woff2")
    assert not allowlist.is_file_allowlisted(entries, "extension_masquerade", "b.woff2")
    assert not allowlist.is_file_allowlisted(entries, "vscode_tasks", "a.woff2")


def test_is_file_line_allowlisted_matches_file_and_line():
    entries = [allowlist.AllowlistEntry("hidden_payload_padding", "app.js:12", "")]
    assert allowlist.is_file_line_allowlisted(entries, "hidden_payload_padding", "app.js", 12)
    assert not allowlist.is_file_line_allowlisted(entries, "hidden_payload_padding", "app.js", 13)
    assert not allowlist.is_file_line_allowlisted(entries, "ioc_literal_match", "app.js", 12)


def test_is_commit_allowlisted_matches_by_prefix():
    # The allowlist stores a short prefix; the scanner passes the full sha
    # and the match checks that the full sha starts with the stored prefix.
    entries = [allowlist.AllowlistEntry("commit_camouflage", "abcdef1", "")]
    assert allowlist.is_commit_allowlisted(entries, "commit_camouflage", "abcdef1")
    assert allowlist.is_commit_allowlisted(entries, "commit_camouflage", "abcdef1234567890")
    assert not allowlist.is_commit_allowlisted(entries, "commit_camouflage", "abcdef99")
    assert not allowlist.is_commit_allowlisted(entries, "clock_tamper_tooling", "abcdef1234567890")


def test_is_commit_allowlisted_rejects_short_identifiers():
    # An identifier shorter than MIN_COMMIT_PREFIX_LEN would match almost any
    # commit as a prefix -- too easy to accidentally allowlist unrelated
    # commits, so short entries are simply never treated as a match.
    entries = [allowlist.AllowlistEntry("commit_camouflage", "abc", "")]
    assert not allowlist.is_commit_allowlisted(entries, "commit_camouflage", "abc12345678")
