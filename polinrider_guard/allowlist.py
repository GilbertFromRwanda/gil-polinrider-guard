"""Shared allowlist for marking a specific finding as reviewed-and-legitimate,
without touching the flagged content (or, for a commit-based finding,
rewriting and re-hashing something that may already be pushed/shared --
that's a real constraint, not a style choice: unlike scan_ioc.py's inline
`# polinrider-guard:ignore` comment, which lives in a source file you can
freely edit, a commit already in history often can't be edited at all
without force-pushing again).

FORMAT
------
One entry per line in a `.polinrider-allowlist` file at the root you scan
(not auto-discovered above that -- if you scan a subdirectory, put the file
there, or scan from the repo root):

    # comment
    scanner_key | identifier | reason

`#`-prefixed and blank lines are ignored. Pipe-delimited, not JSON/YAML, to
stay grep/diff-friendly and add no dependency (this project ships with
none). The reason field is required in spirit, not enforced in code, the
same way a git commit message isn't -- but a scan finding you can't explain
why you dismissed isn't meaningfully reviewed.

Identifier format depends on what the scanner's findings are keyed by:
  - file-based (clock_tamper_tooling, extension_masquerade, vscode_tasks,
    js_ecosystem_attack): the finding's relative file path, exact match.
  - file+line-based (hidden_payload_padding, ioc_literal_match):
    "path:line", exact match.
  - commit-based (commit_camouflage): a prefix of the commit hash, 7+ hex
    characters (same convention as `git log --abbrev-commit`) -- matched as
    a prefix so the full 40-char SHA isn't required.

EXAMPLE
-------
    commit_camouflage | f6e5d4c | prettier reformat commit, reviewed diff, nothing suspicious beyond package-lock.json
    clock_tamper_tooling | scripts/mock-date.sh | intentional test fixture for date-mocking unit tests
    hidden_payload_padding | src/generated/bundle.js:42 | auto-generated minified bundle, safe
    extension_masquerade | assets/fonts/custom.eot | custom font tool's output doesn't match standard EOT magic bytes, verified with `file`
    vscode_tasks | .vscode/tasks.json | team-approved auto-setup task, see docs/onboarding.md

Findings that match are silently dropped from that scanner's results, the
same way scan_ioc.py's ignore-comment findings never appear in the first
place -- there's no separate "N suppressed" report. Malformed lines are
skipped rather than raising, so a typo in this file can't crash a scan.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

ALLOWLIST_FILENAME = ".polinrider-allowlist"
MIN_COMMIT_PREFIX_LEN = 7


@dataclass(frozen=True)
class AllowlistEntry:
    scanner: str
    identifier: str
    reason: str


def load_allowlist(root: str | os.PathLike) -> list[AllowlistEntry]:
    path = Path(root) / ALLOWLIST_FILENAME
    if not path.is_file():
        return []

    entries: list[AllowlistEntry] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 2 or not parts[0] or not parts[1]:
            continue  # malformed -- skip rather than fail the whole scan
        scanner, identifier = parts[0], parts[1]
        reason = parts[2] if len(parts) > 2 else ""
        entries.append(AllowlistEntry(scanner, identifier, reason))
    return entries


def is_file_allowlisted(entries: list[AllowlistEntry], scanner: str, file: str) -> bool:
    return any(e.scanner == scanner and e.identifier == file for e in entries)


def is_file_line_allowlisted(entries: list[AllowlistEntry], scanner: str, file: str, line: int) -> bool:
    identifier = f"{file}:{line}"
    return any(e.scanner == scanner and e.identifier == identifier for e in entries)


def is_commit_allowlisted(entries: list[AllowlistEntry], scanner: str, commit_sha: str) -> bool:
    return any(
        e.scanner == scanner
        and len(e.identifier) >= MIN_COMMIT_PREFIX_LEN
        and commit_sha.startswith(e.identifier)
        for e in entries
    )
