"""Scanner for ForceMemo-style git history backdating.

ForceMemo rebases a malicious commit into a repository's past and
force-pushes it so the commit *looks* like it was authored weeks or months
ago. Git records two timestamps per commit: the author date (the claimed
authorship time, freely rewritable) and the committer date (when the commit
object was actually written, which a rebase/force-push updates to "now").
Legitimate rebases produce gaps of minutes; large backdating leaves a gap of
hours to months. This module walks history and flags outliers.
"""
from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

DEFAULT_THRESHOLD_SECONDS = 6 * 3600  # 6 hours


@dataclass
class GitDateFinding:
    commit: str
    author_date: str
    committer_date: str
    gap_seconds: int
    subject: str
    severity: str

    def to_dict(self) -> dict:
        return {
            "type": "git_date_backdating",
            "commit": self.commit,
            "author_date": self.author_date,
            "committer_date": self.committer_date,
            "gap_seconds": self.gap_seconds,
            "gap_human": _humanize(self.gap_seconds),
            "subject": self.subject,
            "severity": self.severity,
        }


def _humanize(seconds: int) -> str:
    seconds = abs(seconds)
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, _ = divmod(rem, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes and not days:
        parts.append(f"{minutes}m")
    return " ".join(parts) or "0m"


def _severity(gap_seconds: int) -> str:
    days = gap_seconds / 86400
    if days >= 7:
        return "critical"
    if days >= 1:
        return "high"
    return "medium"


class NotAGitRepoError(RuntimeError):
    pass


def scan_path(
    target: str | os.PathLike,
    threshold_seconds: int = DEFAULT_THRESHOLD_SECONDS,
) -> list[GitDateFinding]:
    root = Path(target).resolve()

    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--is-inside-work-tree"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0 or result.stdout.strip() != "true":
        raise NotAGitRepoError(f"{root} is not a git repository")

    # %at / %ct are Unix timestamps (author, committer) -- safe to diff
    # numerically. %H is the full hash, %s the subject, %ad/%cd the
    # human-readable dates for the report.
    fmt = "%H%x1f%at%x1f%ct%x1f%ad%x1f%cd%x1f%s%x1e"
    log = subprocess.run(
        ["git", "-C", str(root), "log", "--all", f"--pretty=format:{fmt}", "--date=iso-strict"],
        capture_output=True,
        text=True,
    )
    if log.returncode != 0:
        raise NotAGitRepoError(f"git log failed in {root}: {log.stderr.strip()}")

    findings: list[GitDateFinding] = []
    for record in log.stdout.split("\x1e"):
        record = record.strip()
        if not record:
            continue
        fields = record.split("\x1f")
        if len(fields) != 6:
            continue
        commit_hash, author_ts, committer_ts, author_date, committer_date, subject = fields
        gap = int(committer_ts) - int(author_ts)
        if abs(gap) < threshold_seconds:
            continue
        findings.append(
            GitDateFinding(
                commit=commit_hash,
                author_date=author_date,
                committer_date=committer_date,
                gap_seconds=gap,
                subject=subject,
                severity=_severity(gap),
            )
        )
    return findings


def main(argv: list[str] | None = None) -> int:
    import argparse
    import json

    parser = argparse.ArgumentParser(
        prog="polinrider-scan-git-dates",
        description="Flag commits with a large author/committer date gap (ForceMemo backdating technique).",
    )
    parser.add_argument("path", help="Path to a git repository")
    parser.add_argument(
        "--threshold-hours",
        type=float,
        default=DEFAULT_THRESHOLD_SECONDS / 3600,
        help="Minimum author/committer gap (hours) to flag (default: 6)",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    args = parser.parse_args(argv)

    try:
        findings = scan_path(args.path, threshold_seconds=int(args.threshold_hours * 3600))
    except NotAGitRepoError as exc:
        print(str(exc))
        return 2

    if args.json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    else:
        if not findings:
            print(f"No suspicious author/committer date gaps found in {args.path}")
        for f in findings:
            print(f"[{f.severity.upper()}] {f.commit[:12]} gap={_humanize(f.gap_seconds)} - {f.subject}")
            print(f"    author date:    {f.author_date}")
            print(f"    committer date: {f.committer_date}")

    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
